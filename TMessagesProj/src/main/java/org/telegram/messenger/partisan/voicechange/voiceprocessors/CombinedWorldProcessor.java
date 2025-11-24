package org.telegram.messenger.partisan.voicechange.voiceprocessors;

import org.telegram.messenger.partisan.voicechange.ParametersProvider;
import org.telegram.messenger.partisan.voicechange.WorldVocoder;

import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

import be.tarsos.dsp.AudioEvent;
import be.tarsos.dsp.io.TarsosDSPAudioFormat;

public class CombinedWorldProcessor extends ChainedAudioProcessor {

    private static final int bufferLengthMs = 350;
    public final int bufferSize;
    public final int bufferOverlap;
    private double currentF0Shift;
    private double currentFormantRatio;

    private final ParametersProvider parametersProvider;
    private final int sampleRate;
    private final float[] outputAccumulator;
    private final long osamp;

    private final ThreadPoolExecutor threadPoolExecutor = new ThreadPoolExecutor(Runtime.getRuntime().availableProcessors(), Runtime.getRuntime().availableProcessors(), 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
    private final ThreadPoolExecutor finalizingQueue = new ThreadPoolExecutor(1, 1, 60, TimeUnit.SECONDS, new LinkedBlockingQueue<>());
    private final BlockingQueue<AudioEvent> audioEventQueue = new LinkedBlockingQueue<>();

    private boolean needFinishProcessing = false;
    private boolean forceFinishProcessing = false;

    public CombinedWorldProcessor(ParametersProvider parametersProvider, int sampleRate) {
        this.parametersProvider = parametersProvider;
        this.sampleRate = sampleRate;

        bufferSize = (int)(bufferLengthMs / 1000.0 * sampleRate) + 1;
        bufferOverlap = 0;

        outputAccumulator = new float[bufferSize * 2];
        osamp = bufferSize / (bufferSize - bufferOverlap);
        initShifts();
    }

    private void initShifts() {
        currentF0Shift = parametersProvider.getF0Shift();
        currentFormantRatio = parametersProvider.getFormantRatio();
        double maxFormantSpread = parametersProvider.getMaxFormantSpread();
        if (maxFormantSpread >= 1E-6) {
            currentF0Shift += ThreadLocalRandom.current().nextDouble(-maxFormantSpread, maxFormantSpread);
            currentFormantRatio += ThreadLocalRandom.current().nextDouble(-maxFormantSpread, maxFormantSpread);
        }
    }

    @Override
    public void processingFinished() {
        synchronized (this) {
            if (!needFinishProcessing) {
                needFinishProcessing = true;
            } else {
                forceFinishProcessing = true;
            }
        }
    }

    @Override
    public boolean process(AudioEvent audioEvent) {
        AudioEvent audioEventCopy = cloneAudioEvent(audioEvent);
        audioEventQueue.add(audioEventCopy);
        final double shiftFrom = currentF0Shift;
        currentF0Shift = generateNewShift(parametersProvider.getF0Shift(), currentF0Shift);
        final double shiftTo = currentF0Shift;
        final double ratioFrom = currentFormantRatio;
        currentFormantRatio = generateNewShift(parametersProvider.getFormantRatio(), currentFormantRatio);
        final double ratioTo = currentFormantRatio;
        threadPoolExecutor.execute(() -> {
            float[] shiftedAudioBuffer = changeVoice(audioEventCopy.getFloatBuffer(), shiftFrom, shiftTo, ratioFrom, ratioTo);
            finalizingQueue.execute(() -> shiftingFinished(audioEventCopy, shiftedAudioBuffer));
        });
        return true;
    }

    private AudioEvent cloneAudioEvent(AudioEvent audioEvent) {
        TarsosDSPAudioFormat dspFormat = new TarsosDSPAudioFormat(sampleRate, 16, 1, true, false);
        AudioEvent audioEventCopy = new AudioEvent(dspFormat);
        audioEventCopy.setOverlap(audioEvent.getOverlap());
        audioEventCopy.setFloatBuffer(audioEvent.getFloatBuffer().clone());
        audioEventCopy.setBytesProcessed(audioEvent.getSamplesProcessed() * dspFormat.getFrameSize());
        return audioEventCopy;
    }

    private double generateNewShift(double defaultValue, double oldValue) {
        if (parametersProvider.getMaxFormantSpread() < 1E-6) {
            return oldValue;
        }
        double newValue;
        double minValue = defaultValue / (1.0 + parametersProvider.getMaxFormantSpread());
        double maxValue = defaultValue * (1.0 + parametersProvider.getMaxFormantSpread());
        do {
            double max_change = parametersProvider.getMaxFormantSpread() * 0.1;
            double change = ThreadLocalRandom.current().nextDouble(-max_change, max_change);
            newValue = oldValue + change;
        } while(newValue < minValue || newValue > maxValue);
        return newValue;
    }

    private float[] changeVoice(float[] srcFloatBuffer, double shiftFrom, double shiftTo, double ratioFrom, double ratioTo) {
        float[] audioBufferResult = new float[srcFloatBuffer.length];
        WorldVocoder.changeVoice(
                shiftFrom,
                shiftTo,
                ratioFrom,
                ratioTo,
                sampleRate,
                srcFloatBuffer,
                srcFloatBuffer.length,
                audioBufferResult,
                parametersProvider.shiftFormantsWithHarvest() ? 1 : 0,
                parametersProvider.getBadSThreshold(),
                parametersProvider.getBadSCutoff(),
                parametersProvider.getBadShMinThreshold(),
                parametersProvider.getBadShMaxThreshold(),
                parametersProvider.getBadShCutoff()
        );
        return audioBufferResult;
    }

    private float clipAudioSample(float value) {
        return Math.max(Math.min(value, 1.0f), -1.0f);
    }

    private void shiftingFinished(AudioEvent audioEvent, float[] shiftedAudioBuffer) {
        boolean currentEventIsFirstInQueue = checkHeadAudioEventInQueueAndRemoveIfNeeded(audioEvent);
        if (!currentEventIsFirstInQueue) {
            finalizingQueue.execute(() -> shiftingFinished(audioEvent, shiftedAudioBuffer));
            return;
        }

        mergeAudioBufferWithOutput(outputAccumulator, shiftedAudioBuffer);
        updateAudioEventBuffer(audioEvent);
        if (nextAudioProcessor != null) {
            nextAudioProcessor.process(audioEvent);
        }
        synchronized (this) {
            if (needFinishProcessing && audioEventQueue.isEmpty() || forceFinishProcessing) {
                actualFinishProcessing();
            }
        }
    }

    private boolean checkHeadAudioEventInQueueAndRemoveIfNeeded(AudioEvent targetAudioEvent) {
        if (audioEventQueue.peek() == targetAudioEvent) {
            try {
                audioEventQueue.take();
                return true;
            } catch (InterruptedException ignore) {
            }
        }
        return false;
    }

    private void mergeAudioBufferWithOutput(float[] outputAccumulator, float[] audioBuffer) {
        if (osamp == 1) {
            Arrays.fill(outputAccumulator, 0f);
        }
        for (int i = 0; i < audioBuffer.length; i++) {
            if (osamp == 1) {
                outputAccumulator[i] = audioBuffer[i];
            } else {
                outputAccumulator[i] = outputAccumulator[i] + audioBuffer[i];
                if (i < bufferOverlap || i > bufferSize - bufferOverlap) {
                    outputAccumulator[i] /= 2;
                }
            }
            outputAccumulator[i] = clipAudioSample(outputAccumulator[i]);
        }
        int stepSize = (int) (bufferSize/osamp);
        if (osamp != 1) {
            System.arraycopy(outputAccumulator, stepSize, outputAccumulator, 0, bufferSize);
        }
    }

    private void updateAudioEventBuffer(AudioEvent audioEvent) {
        int stepSize = (int) (bufferSize/osamp);
        float[] audioBuffer = new float[audioEvent.getFloatBuffer().length];
        audioEvent.setFloatBuffer(audioBuffer);
        System.arraycopy(outputAccumulator, 0, audioBuffer, bufferSize-stepSize, stepSize);
    }

    private void actualFinishProcessing() {
        threadPoolExecutor.shutdown();
        finalizingQueue.shutdown();
        if (nextAudioProcessor != null) {
            nextAudioProcessor.processingFinished();
        }
    }
}

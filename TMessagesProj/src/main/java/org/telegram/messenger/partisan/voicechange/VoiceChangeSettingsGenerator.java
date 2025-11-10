package org.telegram.messenger.partisan.voicechange;

import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import java.util.function.Function;

public class VoiceChangeSettingsGenerator {
    private Random random;

    public void generateParameters(boolean newSeed) {
        if (newSeed) {
            generateNewSeed();
        }
        random = new Random(VoiceChangeSettings.settingsSeed.get().orElse(0L));
        if (VoiceChangeSettings.aggressiveChangeLevel.get().orElse(true)) {
            boolean makeBadSounds = random.nextBoolean();
            if (makeBadSounds) {
                generateBadSoundsParams();
            } else {
                resetBadSoundsParams();
            }
            generateFormantOrSpectrumDistortionParams(makeBadSounds ? 1.3 : 1.4, 1.7);
        } else {
            resetBadSoundsParams();
            generateFormantOrSpectrumDistortionParams(1.15, 1.3);
        }
    }

    private static void generateNewSeed() {
        long seed = 0;
        while (seed == 0) {
            seed = ThreadLocalRandom.current().nextLong();
        }
        VoiceChangeSettings.settingsSeed.set(seed);
    }

    private void generateBadSoundsParams() {
        boolean makeBadShSound = random.nextBoolean();
        if (makeBadShSound) {
            VoiceChangeSettings.badSCutoff.set(0);
            VoiceChangeSettings.badShCutoff.set(random.nextInt(6000, 8000));
        } else {
            VoiceChangeSettings.badSCutoff.set(random.nextInt(3000, 4000));
            VoiceChangeSettings.badShCutoff.set(0);
        }
    }

    private static void resetBadSoundsParams() {
        VoiceChangeSettings.badSCutoff.set(0);
        VoiceChangeSettings.badShCutoff.set(0);
    }

    private void generateFormantOrSpectrumDistortionParams(double min, double max) {
        if (VoiceChangeSettings.useSpectrumDistortion.get().orElse(false)) {
            generateSpectrumDistortionParams(min, max);
        } else {
            generateFormantParams(min, max);
        }
    }

    private void generateSpectrumDistortionParams(double minShift, double maxShift) {
        double sourceShift = random.nextDouble(0.9, 1.1);
        Function<Integer, String> makeShiftParam = src -> {
            int shiftedSrc = (int)(src * sourceShift);
            double destShift = random.nextDouble(minShift, maxShift);
            if (random.nextBoolean()) {
                destShift = 1.0 / destShift;
            }
            int dest = (int)(shiftedSrc * destShift);
            return shiftedSrc + ":" + dest;
        };

        String paramString = makeShiftParam.apply(200) + ","
                + makeShiftParam.apply(600) + ","
                + makeShiftParam.apply(2000) + ","
                + makeShiftParam.apply(6000);

        VoiceChangeSettings.spectrumDistorterParams.set(paramString);

        VoiceChangeSettings.f0Shift.set(1.0f);
        VoiceChangeSettings.formantRatio.set(1.0f);
    }

    private void generateFormantParams(double min, double max) {
        boolean decreasePitch = random.nextBoolean();
        if (decreasePitch) {
            double newMax = 1.0 / min;
            min = 1.0 / max;
            max = newMax;
        }
        VoiceChangeSettings.f0Shift.set((float)random.nextDouble(min, max));
        VoiceChangeSettings.formantRatio.set((float)random.nextDouble(min, max));

        VoiceChangeSettings.spectrumDistorterParams.set("");
    }
}

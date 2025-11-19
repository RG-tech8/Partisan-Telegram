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
            generateFormantOrSpectrumDistortionParams(1.4f, 1.7f);
            setMaxFormantSpreadIfNeeded(generateRandomFloat(0.15f, 0.25f));
        } else {
            resetBadSoundsParams();
            generateFormantOrSpectrumDistortionParams(1.2f, 1.4f);
            setMaxFormantSpreadIfNeeded(0.05f);
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
            VoiceChangeSettings.badShCutoff.set(generateRandomInt(6000, 8000));
        } else {
            VoiceChangeSettings.badSCutoff.set(generateRandomInt(3000, 4000));
            VoiceChangeSettings.badShCutoff.set(0);
        }
    }

    private static void resetBadSoundsParams() {
        VoiceChangeSettings.badSCutoff.set(0);
        VoiceChangeSettings.badShCutoff.set(0);
    }

    private void generateFormantOrSpectrumDistortionParams(float min, float max) {
        if (VoiceChangeSettings.useSpectrumDistortion.get().orElse(false)) {
            generateSpectrumDistortionParams(min, max);
        } else {
            generateFormantParams(min, max);
        }
    }

    private void generateSpectrumDistortionParams(float minShift, float maxShift) {
        float sourceShift = generateRandomFloat(0.9f, 1.1f);
        Function<Integer, String> makeShiftParam = src -> {
            int shiftedSrc = (int)(src * sourceShift);
            float destShift = generateRandomFloat(minShift, maxShift);
            if (random.nextBoolean()) {
                destShift = 1.0f / destShift;
            }
            int dest = (int)(shiftedSrc * destShift);
            return shiftedSrc + ":" + dest;
        };

        String paramString = makeShiftParam.apply(200) + ","
                + makeShiftParam.apply(600) + ","
                + makeShiftParam.apply(2000) + ","
                + makeShiftParam.apply(6000);

        VoiceChangeSettings.spectrumDistortionParams.set(paramString);

        VoiceChangeSettings.f0Shift.set(1.0f);
        VoiceChangeSettings.formantRatio.set(1.0f);
    }

    private void generateFormantParams(float min, float max) {
        boolean decreasePitch = random.nextBoolean();
        if (decreasePitch) {
            float newMax = 1.0f / min;
            min = 1.0f / max;
            max = newMax;
        }
        VoiceChangeSettings.f0Shift.set(generateRandomFloat(min, max));
        VoiceChangeSettings.formantRatio.set(generateRandomFloat(min, max));

        VoiceChangeSettings.spectrumDistortionParams.set("");
    }

    private void setMaxFormantSpreadIfNeeded(float spread) {
        if (VoiceChangeSettings.useSpectrumDistortion.get().orElse(false)) {
            VoiceChangeSettings.maxFormantSpread.set(0.0f);
        } else {
            VoiceChangeSettings.maxFormantSpread.set(spread);
        }
    }

    private int generateRandomInt(int origin, int bound) {
        return random.nextInt(bound - origin) + origin;
    }

    private float generateRandomFloat(float origin, float bound) {
        return random.nextFloat() * (bound - origin) + origin;
    }
}

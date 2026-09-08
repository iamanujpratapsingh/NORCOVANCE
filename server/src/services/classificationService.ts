import { classificationConfig } from '../classificationConfig.js';

export type ColourFeatures = {
  averageRgb: { r: number; g: number; b: number };
  hsv: { hue: number; saturation: number; brightness: number };
  colourDistance: number;
  referenceDetected: boolean;
};

export function classifyColour(features: ColourFeatures) {
  const { hue, saturation, brightness } = features.hsv;
  const positive = hue >= classificationConfig.positive.minHue && hue <= classificationConfig.positive.maxHue && saturation >= classificationConfig.positive.minSaturation && brightness >= classificationConfig.positive.minBrightness;
  const negative = saturation <= classificationConfig.negative.maxSaturation && brightness >= classificationConfig.negative.minBrightness;
  const separation = Math.max(0, 1 - features.colourDistance / 255);
  const confidence = Math.min(0.98, Math.max(0.52, positive || negative ? 0.72 + separation * 0.23 : 0.55 + separation * 0.12));
  const result = positive && confidence >= classificationConfig.inconclusiveConfidenceFloor ? 'POSITIVE' : negative && confidence >= classificationConfig.inconclusiveConfidenceFloor ? 'NEGATIVE' : 'INCONCLUSIVE';
  return {
    result,
    confidence: Number(confidence.toFixed(2)),
    explanation: result === 'POSITIVE' ? 'Observed colour characteristics are consistent with the configured positive reference range.' : result === 'NEGATIVE' ? 'Observed colour characteristics are consistent with the configured negative reference range.' : 'Observed colour characteristics fall between configured reference ranges and require confirmatory review.',
    features
  };
}

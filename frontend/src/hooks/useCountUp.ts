import { useState, useEffect } from 'react';

/**
 * Lightweight, requestAnimationFrame-based counter that animates from 0 (or startValue)
 * to endValue. Respects user's prefers-reduced-motion setting.
 */
export function useCountUp(
  endValue: number,
  durationMs: number = 1000,
  decimals: number = 0,
  startValue: number = 0
): string {
  const [current, setCurrent] = useState<number>(startValue);

  useEffect(() => {
    // If user prefers reduced motion, set immediately
    const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (prefersReducedMotion || durationMs <= 0) {
      setCurrent(endValue);
      return;
    }

    let startTime: number | null = null;
    let animationFrameId: number;

    const animate = (timestamp: number) => {
      if (!startTime) startTime = timestamp;
      const progress = Math.min((timestamp - startTime) / durationMs, 1);
      
      // Smooth easeOutQuart
      const easeOut = 1 - Math.pow(1 - progress, 4);
      const val = startValue + (endValue - startValue) * easeOut;
      
      setCurrent(val);

      if (progress < 1) {
        animationFrameId = requestAnimationFrame(animate);
      } else {
        setCurrent(endValue);
      }
    };

    animationFrameId = requestAnimationFrame(animate);

    return () => {
      if (animationFrameId) {
        cancelAnimationFrame(animationFrameId);
      }
    };
  }, [endValue, durationMs, startValue]);

  return current.toFixed(decimals);
}

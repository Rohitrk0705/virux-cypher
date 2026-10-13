import React, { useEffect, useState } from 'react';
import { useReducedMotion } from 'framer-motion';

interface AnimatedCounterProps {
  value: number;
  duration?: number;
  prefix?: string;
  suffix?: string;
  className?: string;
  style?: React.CSSProperties;
}

export const AnimatedCounter: React.FC<AnimatedCounterProps> = ({
  value,
  duration = 1000,
  prefix = '',
  suffix = '',
  className,
  style,
}) => {
  const prefersReduced = useReducedMotion();
  const [displayValue, setDisplayValue] = useState(prefersReduced ? value : 0);

  useEffect(() => {
    if (prefersReduced) {
      setDisplayValue(value);
      return;
    }

    let start = 0;
    const startTime = performance.now();
    let animId: number;

    const updateCount = (now: number) => {
      const elapsed = now - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease out cubic
      const easeProgress = 1 - Math.pow(1 - progress, 3);
      const current = Math.round(start + (value - start) * easeProgress);
      setDisplayValue(current);

      if (progress < 1) {
        animId = requestAnimationFrame(updateCount);
      } else {
        setDisplayValue(value);
      }
    };

    animId = requestAnimationFrame(updateCount);
    return () => cancelAnimationFrame(animId);
  }, [value, duration, prefersReduced]);

  return (
    <span className={className} style={style}>
      {prefix}
      {displayValue.toLocaleString()}
      {suffix}
    </span>
  );
};

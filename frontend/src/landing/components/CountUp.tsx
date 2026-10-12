'use client';

import { useEffect, useRef } from 'react';
import './CountUp.css';

export interface CountUpProps {
  to: number;
  from?: number;
  direction?: 'up' | 'down';
  delay?: number;
  duration?: number;
  className?: string;
  startWhen?: boolean;
  separator?: string;
  decimals?: number;
  prefix?: string;
  suffix?: string;
}

export function CountUp({
  to,
  from = 0,
  direction = 'up',
  delay = 0,
  duration = 1.8,
  className = '',
  startWhen = true,
  separator = '',
  decimals = 0,
  prefix = '',
  suffix = '',
}: CountUpProps) {
  const ref = useRef<HTMLSpanElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el || !startWhen) return undefined;

    const startVal = direction === 'down' ? to : from;
    const endVal = direction === 'down' ? from : to;

    // Check prefers-reduced-motion
    const reduceMotion =
      typeof window !== 'undefined' &&
      window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;

    if (reduceMotion) {
      el.textContent = `${prefix}${endVal.toFixed(decimals)}${suffix}`;
      return undefined;
    }

    let startTime: number | null = null;
    let rafId: number;
    let timerId: ReturnType<typeof setTimeout>;

    const easeOutExpo = (t: number): number => {
      return t === 1 ? 1 : 1 - Math.pow(2, -10 * t);
    };

    const animate = (timestamp: number) => {
      if (startTime === null) startTime = timestamp;
      const elapsed = Math.max(0, timestamp - startTime);
      const progress = Math.min(1, elapsed / (duration * 1000));
      const easedProgress = easeOutExpo(progress);

      const current = startVal + (endVal - startVal) * easedProgress;
      const formattedNumber = current.toFixed(decimals);

      let formattedString = formattedNumber;
      if (separator) {
        const parts = formattedNumber.split('.');
        parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, separator);
        formattedString = parts.join('.');
      }

      el.textContent = `${prefix}${formattedString}${suffix}`;

      if (progress < 1) {
        rafId = requestAnimationFrame(animate);
      } else {
        const finalFormatted = endVal.toFixed(decimals);
        let finalString = finalFormatted;
        if (separator) {
          const parts = finalFormatted.split('.');
          parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, separator);
          finalString = parts.join('.');
        }
        el.textContent = `${prefix}${finalString}${suffix}`;
      }
    };

    timerId = setTimeout(() => {
      rafId = requestAnimationFrame(animate);
    }, delay * 1000);

    return () => {
      clearTimeout(timerId);
      cancelAnimationFrame(rafId);
    };
  }, [to, from, direction, delay, duration, startWhen, separator, decimals, prefix, suffix]);

  return <span ref={ref} className={`fc-count-up ${className}`.trim()} />;
}

export default CountUp;

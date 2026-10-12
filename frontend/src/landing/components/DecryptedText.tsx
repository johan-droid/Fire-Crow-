'use client';

import { useEffect, useState, useRef, useMemo, useCallback } from 'react';
import type { CSSProperties } from 'react';
import './DecryptedText.css';

export interface DecryptedTextProps {
  text: string;
  speed?: number;
  maxIterations?: number;
  sequential?: boolean;
  revealDirection?: 'start' | 'end' | 'center';
  useOriginalCharsOnly?: boolean;
  characters?: string;
  className?: string;
  parentClassName?: string;
  encryptedClassName?: string;
  animateOn?: 'view' | 'hover' | 'inViewHover' | 'click';
  style?: CSSProperties;
}

export const DecryptedText = ({
  text,
  speed = 40,
  maxIterations = 10,
  sequential = true,
  revealDirection = 'start',
  useOriginalCharsOnly = false,
  characters = '0123456789ABCDEF!@#$%&*<>[]{}',
  className = 'decrypted-char--plain',
  parentClassName = '',
  encryptedClassName = 'decrypted-char--cipher',
  animateOn = 'view',
  style,
}: DecryptedTextProps) => {
  const [displayText, setDisplayText] = useState<string>(text);
  const [isAnimating, setIsAnimating] = useState<boolean>(false);
  const [revealedIndices, setRevealedIndices] = useState<Set<number>>(new Set());
  const [hasAnimated, setHasAnimated] = useState<boolean>(false);
  const [isDecrypted, setIsDecrypted] = useState<boolean>(true);

  const containerRef = useRef<HTMLSpanElement>(null);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const availableChars = useMemo(() => {
    return useOriginalCharsOnly
      ? Array.from(new Set(text.split(''))).filter(char => char !== ' ')
      : characters.split('');
  }, [useOriginalCharsOnly, text, characters]);

  const shuffleText = useCallback(
    (originalText: string, currentRevealed: Set<number>) => {
      return originalText
        .split('')
        .map((char, i) => {
          if (char === ' ') return ' ';
          if (currentRevealed.has(i)) return originalText[i];
          return availableChars[Math.floor(Math.random() * availableChars.length)];
        })
        .join('');
    },
    [availableChars],
  );

  const triggerDecrypt = useCallback(() => {
    if (isAnimating) return;
    setRevealedIndices(new Set());
    setIsDecrypted(false);
    setIsAnimating(true);
  }, [isAnimating]);

  useEffect(() => {
    if (!isAnimating) return undefined;

    let currentIteration = 0;

    intervalRef.current = setInterval(() => {
      setRevealedIndices(prev => {
        if (sequential) {
          if (prev.size < text.length) {
            const nextIndex = revealDirection === 'end' 
              ? text.length - 1 - prev.size 
              : prev.size;
            const updated = new Set(prev);
            updated.add(nextIndex);
            setDisplayText(shuffleText(text, updated));
            return updated;
          }
          if (intervalRef.current) clearInterval(intervalRef.current);
          setIsAnimating(false);
          setIsDecrypted(true);
          setDisplayText(text);
          return prev;
        }

        setDisplayText(shuffleText(text, prev));
        currentIteration++;
        if (currentIteration >= maxIterations) {
          if (intervalRef.current) clearInterval(intervalRef.current);
          setIsAnimating(false);
          setIsDecrypted(true);
          setDisplayText(text);
        }
        return prev;
      });
    }, speed);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [isAnimating, text, speed, maxIterations, sequential, revealDirection, shuffleText]);

  useEffect(() => {
    if (animateOn !== 'view' && animateOn !== 'inViewHover') return undefined;

    const observerCallback = (entries: IntersectionObserverEntry[]) => {
      entries.forEach(entry => {
        if (entry.isIntersecting && !hasAnimated) {
          triggerDecrypt();
          setHasAnimated(true);
        }
      });
    };

    const observer = new IntersectionObserver(observerCallback, { threshold: 0.1 });
    const current = containerRef.current;
    if (current) observer.observe(current);

    return () => {
      if (current) observer.unobserve(current);
    };
  }, [animateOn, hasAnimated, triggerDecrypt]);

  const handleMouseEnter = () => {
    if (animateOn === 'hover' || animateOn === 'inViewHover') {
      triggerDecrypt();
    }
  };

  return (
    <span
      ref={containerRef}
      className={`decrypted-text-wrap ${parentClassName}`.trim()}
      onMouseEnter={handleMouseEnter}
      style={style}
    >
      <span className="decrypted-text__sr">{text}</span>
      <span aria-hidden="true">
        {displayText.split('').map((char, index) => {
          const isRevealed = revealedIndices.has(index) || (!isAnimating && isDecrypted);
          return (
            <span
              key={index}
              className={isRevealed ? className : encryptedClassName}
            >
              {char}
            </span>
          );
        })}
      </span>
    </span>
  );
};

export default DecryptedText;

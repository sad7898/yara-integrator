import React from "react";

export interface ProgressBarProps {
  progress: number;
  className?: string;
}

export const ProgressBar = ({ progress, className }: ProgressBarProps) => {
  return (
    <div className={`h-10 w-full bg-white ${className ?? ""}`}>
      <div
        className="h-10 bg-primary"
        style={{ width: `${progress}%`, transition: "0.2s" }}
      ></div>
    </div>
  );
};

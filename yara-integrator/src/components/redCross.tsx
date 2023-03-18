import { useState } from "react";

interface CrossProps {
  width?: number;
  height?: number;
  onClick?: () => void;
}
export const Cross = ({ width = 50, height = 50, onClick }: CrossProps) => {
  const color = {
    hover: "bg-red-500",
    default: "bg-slate-500",
  };
  const [bgColor, setBgColor] = useState(color.default);
  return (
    <div
      className="relative transform rotate-45"
      style={{ height, width }}
      onClick={onClick}
      onMouseEnter={() => setBgColor(color.hover)}
      onMouseLeave={() => setBgColor(color.default)}
    >
      <div
        className={`absolute top-1/2 left-0 transform -translate-y-1/2 w-full h-2 ${bgColor} duration-200`}
      ></div>
      <div
        className={`absolute top-0 left-1/2 transform -translate-x-1/2 w-2 h-full ${bgColor} duration-200`}
      ></div>
    </div>
  );
};

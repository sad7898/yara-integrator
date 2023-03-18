import React from "react";
interface ButtonProps {
  variant?: "primary" | "secondary" | "alert";
  onClick?: React.MouseEventHandler<HTMLButtonElement>;
  children?: React.ReactNode;
  disabled?: boolean;
  className?: string;
}
export const Button = ({
  variant = "primary",
  onClick,
  children,
  disabled,
}: ButtonProps) => {
  const colorVariants = {
    primary: "bg-primary",
    secondary: "bg-secondary",
    alert: "bg-red-500",
    disabled: "bg-staleGray",
  };
  return (
    <button
      onClick={onClick}
      className={`${
        disabled ? colorVariants["disabled"] : colorVariants[variant]
      } py-2 px-2 rounded-md w-full h-auto`}
      disabled={disabled}
    >
      {children}
    </button>
  );
};

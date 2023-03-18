import React from "react";
interface ButtonProps {
  variant?: "primary" | "secondary" | "alert" | "green";
  onClick?: React.MouseEventHandler<HTMLButtonElement>;
  children?: React.ReactNode;
  disabled?: boolean;
  className?: string;
}
export const Button = ({
  variant = "primary",
  onClick,
  children,
  className,
  disabled,
}: ButtonProps) => {
  const colorVariants = {
    primary:
      "bg-primary text-white duration-200 hover:bg-sage hover:text-black",
    secondary:
      "bg-secondary text-white duration-200 hover:bg-sage hover:text-black",
    alert: "bg-red-500 text-white duration-200 hover:bg-sage hover:text-black",
    disabled: "bg-staleGray text-white",
    green: "bg-correctGreen text-white",
  };
  return (
    <button
      onClick={onClick}
      className={`${
        disabled ? colorVariants["disabled"] : colorVariants[variant]
      } py-2 px-2 rounded-md w-full h-auto ${className}`}
      disabled={disabled}
    >
      {children}
    </button>
  );
};

import React from "react";
interface BlockProps {
  children?: React.ReactNode;
  className?: string;
}
export const Block = ({ children, className }: BlockProps) => {
  return (
    <section
      className={`${className} max-h-4xl max-w-3xl min-w-[650px] bg-white rounded-md p-5`}
    >
      {children}
    </section>
  );
};

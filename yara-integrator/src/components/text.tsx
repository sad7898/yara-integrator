import Link from "next/link";
import * as React from "react";

interface AnchorProps {
  children?: string;
  className?: string;
  link: string;
}

export const Anchor = ({ children, className, link }: AnchorProps) => {
  return (
    <Link
      href={link}
      className={`flex items-center px-1 duration-200 hover:bg-secondary ${className}`}
    >
      {children}
    </Link>
  );
};

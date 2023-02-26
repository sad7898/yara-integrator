import Link from "next/link";
import * as React from "react";

interface AnchorProps {
  children?: string;
  className?: string;
  link: string;
}

export const Anchor = ({ children, className, link }: AnchorProps) => {
  return (
    <Link href={link}>
      <span className={className}>{children}</span>
    </Link>
  );
};

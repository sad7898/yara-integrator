import React, { ChangeEvent, useRef } from "react";
import { Button } from "./button";

export interface UploadFormProps {
  onFileChange: (event: ChangeEvent<HTMLInputElement>) => void;
  children?: React.ReactNode;
  className?: string;
}

export const UploadButton = ({
  onFileChange,
  children,
  className,
}: UploadFormProps) => {
  const inputRef = useRef<HTMLInputElement>(null);
  return (
    <>
      <Button className={className} onClick={() => inputRef.current?.click()}>
        {children}
      </Button>
      <input
        ref={inputRef}
        className="opacity-0 absolute"
        style={{ zIndex: -1 }}
        type="file"
        onChange={onFileChange}
      ></input>
    </>
  );
};

import React from "react";
import { Button } from "../button";

export interface TableProps {
  children: React.ReactNode;
  headers: string[];
  onClickHeader?: (header: string) => void;
}
export const Table = ({ headers, onClickHeader, children }: TableProps) => {
  return (
    <div
      className="grid w-full rounded-2xl"
      style={{
        gridTemplateColumns: `repeat(${headers.length}, minmax(0, 1fr))`,
      }}
    >
      {headers.map((header, indx) => (
        <div
          className="bg-battleshipGray p-3 font-bold"
          key={`${header}-${indx}`}
          onClick={onClickHeader ? () => onClickHeader(header) : undefined}
        >
          {header}
        </div>
      ))}
      {children}
    </div>
  );
};

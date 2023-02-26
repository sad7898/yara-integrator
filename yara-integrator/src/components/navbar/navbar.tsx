import * as React from "react";
import { useState, useEffect } from "react";
import { Anchor } from "../text";
export const Navbar = () => {
  return (
    <nav className="fixed bg-primary w-full px-2 py-3">
      <div className="flex flex-row">
        <div className="mx-8">
          <span className="text-3xl font-semibold text-white">Scandina</span>
        </div>
        <div className="flex space-x-12 items-center">
          <Anchor link="/">Manage YARA</Anchor>
          <Anchor link="/">Contact</Anchor>
        </div>
      </div>
    </nav>
  );
};

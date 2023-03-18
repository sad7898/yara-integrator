import * as React from "react";
import { useState, useEffect } from "react";
import { Anchor } from "../text";
export const Navbar = () => {
  return (
    <nav className="fixed bg-primary w-full px-2 py-3">
      <div className="flex flex-row">
        <div className="mx-8">
          <Anchor link="/" className="text-3xl font-semibold text-white">
            Scandina
          </Anchor>
        </div>
        <div className="flex space-x-12 items-center">
          <Anchor link="/rules">Manage YARA</Anchor>
          <Anchor link="/">Contact</Anchor>
        </div>
      </div>
    </nav>
  );
};

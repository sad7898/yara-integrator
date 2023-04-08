import Link from "next/link";
import * as React from "react";
import { useState, useEffect } from "react";
import { Anchor } from "../text";
export const Navbar = () => {
  return (
    <nav className="fixed bg-primary w-full px-2">
      <div className="flex flex-row h-16">
        <div className="mx-8 flex items-center">
          <Link href="/" className="text-3xl font-semibold text-white">
            Scandina
          </Link>
        </div>
        <div className="flex">
          <Anchor link="/rules" className="px-5">
            Manage YARA
          </Anchor>
          <Anchor link="/setting" className="px-5">
            Setting
          </Anchor>
        </div>
      </div>
    </nav>
  );
};

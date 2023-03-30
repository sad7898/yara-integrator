import React from "react";
import styles from "@/styles/Home.module.css";

const Custom404 = () => {
  return (
    <main
      className={
        styles.main + " flex flex-col justify-center items-center bg-bg"
      }
    >
      <h1 className="text-bold font-3xl">Error 404</h1>
      <h2 className="font-xl">
        Resource you are looking for is not found in the server, please try
        again.
      </h2>
    </main>
  );
};

export default Custom404;

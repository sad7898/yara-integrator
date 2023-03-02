import Head from "next/head";
import Image from "next/image";
import { Inter } from "@next/font/google";
import styles from "@/styles/Home.module.css";
import { ChangeEvent, useEffect, useState } from "react";
import { Navbar } from "@/components/navbar/navbar";
import { useUploadForm } from "@/hooks/useFormUpload";
import { Button } from "@/components/button";
import { UploadButton } from "@/components/uploadButton";
import { ProgressBar } from "@/components/progressBar";
import fileIcon from "../assets/file.png";
import zipIcon from "../assets/zip-folder.png";
const inter = Inter({ subsets: ["latin"] });

export default function Home() {
  const { onSubmit, isSuccess, progress, handleFileChange, apk } =
    useUploadForm(process.env.YARA_API_URL ?? "http://127.0.0.1:5000/scan");

  return (
    <>
      <Navbar />
      <main className={styles.main + " bg-bg"}>
        <div className="flex flex-col justify-between w-3/12 min-w-[350px] min-h-[425px]">
          <div className="flex flex-col items-center w-full">
            {apk && <span className="text-black mb-2">{apk.name}</span>}
            <Image
              src={apk ? zipIcon : fileIcon}
              width={200}
              height={300}
            ></Image>
            :<ProgressBar className="mt-5" progress={progress}></ProgressBar>
          </div>
          <div>
            <div className="flex flex-row space-x-5 mb-3">
              <UploadButton onFileChange={handleFileChange}>
                Upload File
              </UploadButton>
              <Button>Import YARA</Button>
            </div>
            <div className="w-full">
              <Button onClick={onSubmit} disabled={!apk}>
                SCAN
              </Button>
            </div>
          </div>
        </div>
      </main>
    </>
  );
}

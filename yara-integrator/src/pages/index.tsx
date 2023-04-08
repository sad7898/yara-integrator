import Head from "next/head";
import Image from "next/image";
import { Inter } from "@next/font/google";
import styles from "@/styles/Home.module.css";
import { ChangeEvent, useEffect, useState } from "react";
import { Navbar } from "@/components/layout/navbar";
import { useUploadForm } from "@/hooks/useFormUpload";
import { Button } from "@/components/button";
import { UploadButton } from "@/components/uploadButton";
import { ProgressBar } from "@/components/progressBar";
import fileIcon from "../assets/file.png";
import zipIcon from "../assets/zip-folder.png";
import { useRouter } from "next/router";
const inter = Inter({ subsets: ["latin"] });

export default function Home() {
  const router = useRouter();
  const handleResponse = async (response?: any) => {
    if (response.data) {
      console.log(response.data);
      const blob = new Blob([response.data], { type: "application/pdf" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `${file?.name}-report.pdf`;
      a.click();
    }
  };
  const { onSubmit, error, progress, handleFileChange, file } = useUploadForm(
    "/scan",
    handleResponse,
    { responseType: "blob" }
  );

  return (
    <main
      className={
        styles.main + " flex flex-col justify-center items-center bg-bg"
      }
    >
      <div className="flex flex-col justify-between w-3/12 min-w-[350px] min-h-[425px]">
        <div className="flex flex-col items-center w-full">
          {file && <span className="text-black mb-2">{file.name}</span>}
          <Image
            src={file ? zipIcon : fileIcon}
            width={200}
            height={300}
            alt={""}
          ></Image>
          <ProgressBar className="mt-5" progress={progress}></ProgressBar>
        </div>
        <div>
          <div className="flex flex-row space-x-5 mb-3">
            <UploadButton onFileChange={handleFileChange}>
              Upload File
            </UploadButton>
            <Button onClick={() => router.push("/rules/create")}>
              Import YARA
            </Button>
          </div>
          <div className="w-full">
            <Button onClick={() => onSubmit()} disabled={!file}>
              SCAN
            </Button>
          </div>
        </div>
        <div className="text-black">
          **Make sure to configure MobSF API url and API key in setting page
        </div>
        {error && <div className="text-red-500">{error}</div>}
      </div>
    </main>
  );
}

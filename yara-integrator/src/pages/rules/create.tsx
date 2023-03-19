import React, { ChangeEvent, useEffect, useState } from "react";
import styles from "@/styles/Home.module.css";
import { Block } from "@/components/block";
import { Button } from "@/components/button";
import { useUploadForm } from "@/hooks/useFormUpload";
import { UploadButton } from "@/components/uploadButton";
import { Cross } from "@/components/redCross";
import { ProgressBar } from "@/components/progressBar";

const CreateRule = () => {
  const { onSubmit, error, progress, handleFileChange, file, removeFile } =
    useUploadForm("/yara");
  const [filename, setFilename] = useState("");
  const onFileNameChange = (e: ChangeEvent<HTMLInputElement>) => {
    setFilename(e.target.value);
  };
  useEffect(() => {
    if (file) {
      setFilename(file.name);
    } else setFilename("");
  }, [file]);
  return (
    <main
      className={
        styles.main + " bg-bg flex flex-col items-center justify-center"
      }
    >
      <Block className="flex flex-col text-black gap-y-5">
        <h1 className="font-bold text-3xl">Add new YARA rule</h1>
        <div className="flex flex-col gap-y-3 mt-5 mb-8">
          <input
            type="text"
            className="border p-2"
            placeholder="File name"
            value={filename}
            onChange={onFileNameChange}
          ></input>
          {!file ? (
            <UploadButton
              onFileChange={handleFileChange}
              className="max-w-[172px]"
            >
              Upload File
            </UploadButton>
          ) : (
            <div style={{ display: "inherit" }}>
              <Button variant="green" className="max-w-[172px] mr-2">
                {file.name}
              </Button>
              <Cross width={40} height={40} onClick={removeFile}></Cross>
            </div>
          )}
        </div>
        <div>
          <Button className="max-w-[172px]" onClick={onSubmit}>
            Submit
          </Button>
        </div>
        {error && <div className="text-red-500">{error}</div>}
      </Block>
    </main>
  );
};
export default CreateRule;

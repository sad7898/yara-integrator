import React, { ChangeEvent, useEffect, useState } from "react";
import styles from "@/styles/Home.module.css";
import { Block } from "@/components/block";
import { Button } from "@/components/button";
import { useUploadForm } from "@/hooks/useFormUpload";
import { UploadButton } from "@/components/uploadButton";
import { Cross } from "@/components/redCross";
import { ProgressBar } from "@/components/progressBar";
import { useRouter } from "next/router";

const CreateRule = () => {
  const router = useRouter();
  const { onSubmit, error, progress, handleFileChange, file, removeFile } =
    useUploadForm("/yara", () => router.push("/rules"));
  const [filename, setFilename] = useState("");
  const [description, setDescription] = useState("");
  const onFileNameChange = (e: ChangeEvent<HTMLInputElement>) => {
    setFilename(e.target.value);
  };
  const onDescriptionChange = (e: ChangeEvent<HTMLTextAreaElement>) => {
    setDescription(e.target.value);
  };
  const handleSubmit = () => {
    const formData = new FormData();
    formData.append("name", filename);
    formData.append("description", description);
    onSubmit(formData);
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
        <div className="flex flex-col gap-y-3 mt-2 mb-8">
          <label>Name</label>
          <input
            type="text"
            className="border p-2"
            placeholder="File name"
            value={filename}
            onChange={onFileNameChange}
          ></input>
          <label>Description</label>
          <textarea
            className="border w-full min-h-[200px] px-1 py-1"
            required
            value={description}
            onChange={onDescriptionChange}
          />
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
          <Button className="max-w-[172px]" onClick={handleSubmit}>
            Submit
          </Button>
        </div>
        {error && <div className="text-red-500">{error}</div>}
      </Block>
    </main>
  );
};
export default CreateRule;

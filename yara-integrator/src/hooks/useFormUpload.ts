import { client } from "@/utils/axiosInstance";
import axios from "axios";
import * as React from "react";
import { useState, useEffect, ChangeEvent } from "react";

export const useUploadForm = (route: string) => {
  const [isSuccess, setIsSuccess] = useState(false);
  const [progress, setProgress] = useState(0);
  const [file, setFile] = useState<File>();
  const onSubmit = async () => {
    const formData = new FormData();
    formData.append("file", file ?? "");
    const result = await uploadForm(formData);
    alert(`${result.status}:${JSON.stringify(result.data)}`);
  };
  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (progress > 0) setProgress(0);
    if (event.target.files?.length) {
      setFile(event.target.files[0]);
    }
  };
  const removeFile = () => {
    setIsSuccess(false);
    if (progress > 0) setProgress(0);
    setFile(undefined);
  };
  const uploadForm = async (formData: FormData) => {
    setProgress(0);
    const result = await client.post(route, formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
      onUploadProgress: (progressEvent) => {
        if (progressEvent?.total) {
          const progress = (progressEvent.loaded / progressEvent.total) * 100;
          setProgress(progress);
        }
      },
    });
    return result;
  };

  return { isSuccess, progress, file, onSubmit, handleFileChange, removeFile };
};

import axios from "axios";
import * as React from "react";
import { useState, useEffect, ChangeEvent } from "react";

export const useUploadForm = (url: string) => {
  const [isSuccess, setIsSuccess] = useState(false);
  const [progress, setProgress] = useState(0);
  const [apk, setApk] = useState<File>();
  const onSubmit = async () => {
    const formData = new FormData();
    formData.append("file", apk ?? "");
    const result = await uploadForm(formData);
    console.log(result.data);
    alert(`${result.status}:${JSON.stringify(result.data)}`);
  };
  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (progress > 0) setProgress(0);
    if (event.target.files?.length) {
      setApk(event.target.files[0]);
    }
  };
  const uploadForm = async (formData: FormData) => {
    setProgress(0);
    const result = await axios.post(url, formData, {
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

  return { isSuccess, progress, apk, onSubmit, handleFileChange };
};

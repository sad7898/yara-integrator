import { client } from "@/utils/axiosInstance";
import axios, { Axios, AxiosError } from "axios";
import * as React from "react";
import { useState, useEffect, ChangeEvent } from "react";

export const useUploadForm = (route: string, onSubmitCallback?: () => void) => {
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(0);
  const [file, setFile] = useState<File>();
  const onSubmit = async (filename = "") => {
    const formData = new FormData();
    if (filename) formData.append("name", filename);
    formData.append("file", file ?? "");
    setProgress(0);
    setError("");
    let result;
    await client
      .post(route, formData, {
        headers: {
          "Content-Type": "multipart/form-data",
        },
        onUploadProgress: (progressEvent) => {
          if (progressEvent?.total) {
            const progress = (progressEvent.loaded / progressEvent.total) * 100;
            setProgress(progress);
          }
        },
      })
      .then(({ data }) => {
        result = data;
        if (onSubmitCallback) onSubmitCallback();
      })
      .catch((err: AxiosError<any, any>) => {
        setProgress(0);
        setFile(undefined);
        setError(err?.response?.data.error);
      });
    console.log(result);
    return result;
  };
  const handleFileChange = (event: ChangeEvent<HTMLInputElement>) => {
    if (progress > 0) setProgress(0);
    if (event.target.files?.length) {
      setFile(event.target.files[0]);
    }
  };
  const removeFile = () => {
    setError("");
    if (progress > 0) setProgress(0);
    setFile(undefined);
  };

  return { error, progress, file, onSubmit, handleFileChange, removeFile };
};

import axios from "axios";
import * as React from "react";
import { useState, useEffect } from "react";

export const useUploadForm = (url: string) => {
  const [isSuccess, setIsSuccess] = useState(false);
  const [progress, setProgress] = useState(0);

  const uploadForm = async (formData: FormData) => {
    await axios.post(url, formData, {
      headers: {
        "Content-Type": "multipart/form-data",
      },
      onUploadProgress: (progressEvent) => {
        if (progressEvent?.total) {
          const progress = (progressEvent.loaded / progressEvent.total) * 50;
          setProgress(progress);
        }
      },
    });
    setIsSuccess(true);
  };

  return { uploadForm, isSuccess, progress };
};

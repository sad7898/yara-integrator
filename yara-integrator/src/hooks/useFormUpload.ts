import { client } from "@/utils/axiosInstance";
import axios, {
  Axios,
  AxiosError,
  AxiosRequestConfig,
  AxiosResponse,
} from "axios";
import * as React from "react";
import { useState, useEffect, ChangeEvent } from "react";
interface FileProperty {
  name?: string;
  description?: string;
}
export const useUploadForm = (
  route: string,
  onSuccessCallback?: (response?: AxiosResponse<any, any>) => void,
  axiosConfig?: AxiosRequestConfig<FormData>
) => {
  const [error, setError] = useState("");
  const [progress, setProgress] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [file, setFile] = useState<File>();
  const onSubmit = async (additionalData = new FormData()) => {
    setIsLoading(true);
    additionalData.append("file", file ?? "");
    setProgress(0);
    setError("");
    const result = await client
      .post(route, additionalData, {
        ...axiosConfig,
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
      .then((res) => {
        if (onSuccessCallback) onSuccessCallback(res);
        setIsLoading(false);
        return res.data;
      })
      .catch(async (err: AxiosError<any, any>) => {
        setIsLoading(false);
        setProgress(0);
        if (
          err.response?.data instanceof Blob &&
          err.response?.data?.type === "application/json"
        )
          setError(await err.response?.data?.text());
        else setError(err.response?.data.error);
      });
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

  return {
    error,
    progress,
    file,
    onSubmit,
    handleFileChange,
    removeFile,
    isLoading,
  };
};

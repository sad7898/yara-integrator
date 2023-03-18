import axios, { Axios } from "axios";

export const client = axios.create({
  baseURL: process.env.YARA_API_URL ?? "http://127.0.0.1:5000",
});

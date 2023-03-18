import { useRouter } from "next/router";
import React, { useEffect, useState } from "react";
import styles from "@/styles/Home.module.css";
import { client } from "@/utils/axiosInstance";
import { Button } from "@/components/button";
import { Block } from "@/components/block";

const Rule = () => {
  const router = useRouter();
  const [name, setName] = useState("");
  const [content, setContent] = useState("");
  const { rule } = router.query;
  const fetchRule = async (ruleName: string) => {
    const { data } = await client.get(`/yara/${encodeURI(ruleName)}`);
    if (data.data) {
      setName(data.data.name);
      setContent(data.data.content);
    }
  };
  useEffect(() => {
    if (rule && rule.length > 0) {
      if (Array.isArray(rule)) fetchRule(rule[0]);
      else fetchRule(rule);
    }
  }, [rule]);
  return (
    <main
      className={`${styles.main} bg-bg flex flex-col items-center justify-center`}
    >
      <Block className="flex flex-col text-black gap-y-5">
        <h1 className="font-bold text-3xl">Edit</h1>
        <div className="flex flex-col ">
          <label>Name</label>
          <input
            type="text"
            className="border p-2"
            value={name}
            onChange={(e) => setName(e.target.value)}
          ></input>
        </div>
        <div className="flex flex-col">
          <label>Content</label>
          <textarea
            className="border w-full min-h-[450px] px-1 py-1"
            value={content}
            onChange={(e) => setContent(e.target.value)}
          ></textarea>
        </div>
        <div className="flex flex-row gap-x-2">
          <Button variant="primary">Save</Button>
          <Button variant="secondary" onClick={() => router.replace("/rules")}>
            Cancel
          </Button>
        </div>
      </Block>
    </main>
  );
};

export default Rule;

import React, { useCallback, useEffect, useState } from "react";
import styles from "@/styles/Home.module.css";
import { Button } from "@/components/button";
import { client } from "@/utils/axiosInstance";
import { Table } from "@/components/table/table";
import { RuleRow, Rule } from "@/components/ruleRow";
import { useRouter } from "next/router";

export default function Rules() {
  const [rules, setRules] = useState<Rule[]>([]);
  const [selectedRules, setSelectedRules] = useState<Rule[]>([]);
  const router = useRouter();
  const fetchRules = useCallback(async () => {
    const { data } = await client.get("/yara");
    setRules(data.data);
  }, []);
  useEffect(() => {
    fetchRules();
  }, [fetchRules]);
  const onDeleteRules = useCallback(async () => {
    client
      .post("/yara/remove", { data: selectedRules.map((rule) => rule.name) })
      .then(({ data }) => {
        console.log(data);
      })
      .catch((err) => alert(err))
      .finally(() => {
        fetchRules();
      });
  }, [fetchRules, selectedRules]);
  const onSelectRow = (rule: Rule) => {
    const filteredRules = selectedRules.filter(
      (selected) => selected.name !== rule.name
    );
    if (selectedRules.length !== filteredRules.length)
      setSelectedRules(filteredRules);
    else setSelectedRules((prev) => [...prev, rule]);
  };
  return (
    <main className={styles.main + " bg-bg flex flex-col items-center"}>
      <section className="w-3/5 max-w-6xl">
        <div className="flex flex-row justify-between w-full mb-2">
          <h1 className="text-black text-5xl">YARA Rules</h1>
          <div className="flex flex-row gap-4 h-10">
            <Button onClick={onDeleteRules}>Delete</Button>
            <Button onClick={() => router.push("/rules/create")}>New</Button>
          </div>
        </div>
        <Table headers={["Name", "", ""]}>
          {rules.map((rule) => (
            <RuleRow
              onSelectRow={() => onSelectRow(rule)}
              {...rule}
              key={rule.name}
            />
          ))}
        </Table>
      </section>
    </main>
  );
}

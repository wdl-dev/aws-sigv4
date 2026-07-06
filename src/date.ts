// SPDX-FileCopyrightText: 2026 Sean Consulting OÜ
// SPDX-License-Identifier: Apache-2.0

import { ISO_DATE_RE, SIGNING_DATE_ERROR } from "./constants.js";

export function optionalAmzDate(value: unknown): string | undefined {
  if (value === undefined || value === null) {
    return undefined;
  }
  return formatAmzDate(value as string | Date);
}

export function formatAmzDate(value: string | Date): string {
  if (typeof value === "string" && /^\d{8}T\d{6}Z$/u.test(value)) {
    if (!isValidCompactAmzDate(value)) {
      throw new TypeError(SIGNING_DATE_ERROR);
    }
    return value;
  }
  if (typeof value === "string" && !ISO_DATE_RE.test(value)) {
    throw new TypeError(SIGNING_DATE_ERROR);
  }
  if (typeof value === "string" && !isValidIsoDate(value)) {
    throw new TypeError(SIGNING_DATE_ERROR);
  }
  const date = typeof value === "string" ? new Date(value) : value;
  if (!(date instanceof Date)) {
    throw new TypeError(SIGNING_DATE_ERROR);
  }
  if (Number.isNaN(dateTimeValue(date))) {
    throw new TypeError(SIGNING_DATE_ERROR);
  }
  const amzDate = Date.prototype.toISOString.call(date).replace(/[:-]|\.\d{3}/g, "");
  if (!/^\d{8}T\d{6}Z$/u.test(amzDate) || !isValidCompactAmzDate(amzDate)) {
    throw new TypeError(SIGNING_DATE_ERROR);
  }
  return amzDate;
}

function dateTimeValue(date: Date): number {
  try {
    return Date.prototype.getTime.call(date);
  } catch {
    throw new TypeError(SIGNING_DATE_ERROR);
  }
}

function isValidIsoDate(value: string): boolean {
  const match = ISO_DATE_RE.exec(value);
  if (!match) {
    return false;
  }
  const [datePart, timePart] = value.split("T") as [string, string];
  const [yearText, monthText, dayText] = datePart.split("-") as [string, string, string];
  const [hourText, minuteText, secondText] = timePart.split(/[.:Z+-]/u) as [string, string, string];
  return isValidDateParts(
    Number(yearText),
    Number(monthText),
    Number(dayText),
    Number(hourText),
    Number(minuteText),
    Number(secondText)
  );
}

function isValidCompactAmzDate(value: string): boolean {
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(4, 6));
  const day = Number(value.slice(6, 8));
  const hour = Number(value.slice(9, 11));
  const minute = Number(value.slice(11, 13));
  const second = Number(value.slice(13, 15));
  return isValidDateParts(year, month, day, hour, minute, second);
}

function isValidDateParts(
  year: number,
  month: number,
  day: number,
  hour: number,
  minute: number,
  second: number
): boolean {
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  date.setUTCFullYear(year);
  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day &&
    date.getUTCHours() === hour &&
    date.getUTCMinutes() === minute &&
    date.getUTCSeconds() === second
  );
}

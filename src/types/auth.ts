import type { UserRow } from "./db";

export type ViewerContext = {
  userId: string;
  user: UserRow;
};

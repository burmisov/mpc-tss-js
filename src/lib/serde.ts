type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

export interface ToJSONable {
  toJSON(): Json;
};

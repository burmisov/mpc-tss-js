type Json = string | number | boolean | null | Json[] | { [key: string]: Json };

export interface JSONable {
  toJSON(): Json;

  // Don't want to work this around for now.
  // https://github.com/microsoft/TypeScript/issues/33892
  // fromJSON(json: Json): this;
};

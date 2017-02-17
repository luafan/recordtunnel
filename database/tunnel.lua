return {
  ["recordproxy"] = {
    ["path"] = "varchar(255) NOT NULL",
    ["host"] = "varchar(255) NOT NULL",
    ["port"] = "int(5) NOT NULL",
    ["hostname"] = "varchar(255)",
    ["created"] = "bigint NOT NULL",
  },
  ["recordpart"] = {
    ["record"] = "int(11) NOT NULL",
    ["type"] = "enum('request','response') DEFAULT 'request'",
    ["data"] = "blob NOT NULL",
    ["length"] = "int(11) NOT NULL",
    ["created"] = "bigint NOT NULL",

    "INDEX `record` (`record`)",
  }
}

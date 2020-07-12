exports.seed = async function (knex) {
  await knex("users").insert([
    {
      username: "jamjarr",
      password: "asdf123",
    },
    {
      username: "jamjarr1",
      password: "asdf123",
    },
    {
      username: "jamjarr2",
      password: "asdf123",
    },
  ]);
};

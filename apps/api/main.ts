import autoload from "@fastify/autoload";
import Fastify from "fastify";
import path from "path";

const fastify = Fastify({
  logger: {
    transport: {
      target: "pino-pretty",
      options: {
        translateTime: "HH:MM:ss Z",
        ignore: "pid,hostname",
      },
    },
  },
});

fastify.register(autoload, {
  dir: path.join(__dirname, "routes"),
});

async function start() {
  try {
    await fastify.listen({ port: 4000 });
  } catch (err) {
    fastify.log.error(err);
    process.exit(1);
  }
}

start();

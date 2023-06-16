import type { FastifyInstance } from "fastify";
import { z } from "zod";
import { createSigner, createDecoder } from "fast-jwt";
import { prisma } from "@/utils/db";
import argon2 from "argon2";

export default function authRoutes(
  fastify: FastifyInstance,
  opts: unknown,
  done: () => void
) {
  fastify.post("/auth/signup", async (req, reply) => {
    const schema = z.object({
      username: z.string().max(64),
      email: z.string().email(),
      password: z.string(),
    });

    try {
      const body = schema.parse(req.body);
      const password = await argon2.hash(body.password);
      const signer = createSigner({ expiresIn: 24 * 60 * 30 });

      const user = await prisma.user.create({
        data: {
          username: body.username,
          displayName: body.username,
          email: body.email,
          password,
        },
      });

      const token = signer({ id: user.id, email: user.email });

      return {
        token,
      };
    } catch (error) {
      reply.code(400).send({ error });
      return;
    }
  });

  fastify.post("/auth/login", async (req, reply) => {
    const usernameSchema = z.object({
      username: z.string().max(64),
      password: z.string(),
    });

    const emailSchema = z.object({
      email: z.string().email(),
      password: z.string(),
    });

    const body = req.body as any;

    let user;

    if (usernameSchema.safeParse(body).success) {
      user = await prisma.user.findUnique({
        where: { username: body.username },
      });
    } else if (emailSchema.safeParse(body).success) {
      user = await prisma.user.findUnique({ where: { email: body.email } });
    } else {
      reply.code(400).send({ error: "Invalid input" });
      return;
    }

    if (!user) {
      reply.code(400).send({ error: "User not found" });
      return;
    }

    const valid = await argon2.verify(user.password, body.password);

    if (!valid) {
      reply.code(400).send({ error: "Incorrect password" });
      return;
    }

    const signer = createSigner({ expiresIn: 24 * 60 * 30 });
    const token = signer({ id: user.id, email: user.email });

    return {
      token,
    };
  });

  done();
}

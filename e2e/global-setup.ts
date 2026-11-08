import net from 'node:net'

/**
 * A TCP forwarder from localhost:<E2E_PORT> to nginx:80 in the compose network. It changes no bytes, so the
 * browsers see nginx's own headers. The runner process stays alive while the workers run, and so does the listener.
 */
export default async function globalSetup(): Promise<void> {
  const port = Number(process.env['E2E_PORT'] ?? '8080')
  const upstream = process.env['E2E_UPSTREAM'] ?? 'nginx'

  await new Promise<void>((resolve, reject) => {
    const server = net.createServer((client) => {
      const up = net.connect(80, upstream)
      client.pipe(up)
      up.pipe(client)
      client.on('error', () => up.destroy())
      up.on('error', () => client.destroy())
    })
    server.on('error', reject)
    server.listen(port, 'localhost', () => resolve())
  })
}

import { useEffect, useRef } from 'react'
import AnsiToHtml from 'ansi-to-html'

const converter = new AnsiToHtml({ escapeXML: true, newline: true })

interface Props {
  lines: string[]
  height?: string
}

export default function LogTerminal({ lines, height = 'h-[60vh]' }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [lines])

  const html = lines
    .map(l => {
      try { return converter.toHtml(l) }
      catch { return l }
    })
    .join('\n')

  return (
    <div
      className={`terminal ${height} overflow-y-auto rounded-md`}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  )
}

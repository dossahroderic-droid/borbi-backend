import type { AppProps } from 'next/app'
import { Toaster } from 'react-hot-toast'
import '../styles/globals.css'

export default function App({ Component, pageProps }: AppProps) {
  return (
    <>
      <Toaster position="top-right" />
      <Component {...pageProps} />
    </>
  )
}

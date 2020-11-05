using System;
using System.Collections.Generic;
using System.Windows;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Numerics;
using System.Security.Cryptography;


namespace Client_WPF
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            RSAmanipulations();
            SessionKeyManipulations();
        }

        #region RSA        

        const int p = 149;
        const int q = 199;

        long closeKey;
        long n;

        private long CalculateCloseKey(long m)
        {
            long d = m - 1;

            for (long i = 2; i <= m; i++)
                if ((m % i == 0) && (d % i == 0)) //если имеют общие делители
                {
                    d--;
                    i = 1;
                }

            return d;
        }

        private long CalculateOpenKey(long d, long m)
        {
            long e = 10;

            while (true)
            {
                if ((e * d) % m == 1)
                    break;
                else
                    e++;
            }

            return e;
        }

        private void GenerateRSA(out long e, out long d, out long n)
        {
            n = p * q;
            long m = (p - 1) * (q - 1);
            d = CalculateCloseKey(m);
            e = CalculateOpenKey(d, m);
        }

        private void SendOpenKeyToServer(long openKey, long n)
        {
            //адрес сервера
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://localhost:44393/Home/PostRSA");
            request.Method = "Post";

            string dataToSend = "openKey=" + openKey + "&n=" + n;
            request.ContentLength = dataToSend.Length;
            request.ContentType = "application/x-www-form-urlencoded";
            byte[] dataInByteArray = System.Text.Encoding.UTF8.GetBytes(dataToSend);
            using (Stream requestStream = request.GetRequestStream())
            {
                requestStream.Write(dataInByteArray, 0, dataInByteArray.Length);
            }

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            using (Stream stream = response.GetResponseStream())
            {
                string sendingResult = "";
                using (StreamReader reader = new StreamReader(stream))
                {
                    string line = "";
                    while ((line = reader.ReadLine()) != null)
                        sendingResult += line;

                    if (!sendingResult.Equals("OK"))
                    {
                        lMessage.Content = sendingResult;
                    }
                    else
                    {
                        lMessage.Content = "";
                    }
                }
            }
        }

        private void RSAmanipulations()
        {
            GenerateRSA(out long openKey, out long closeKey, out long n);
            this.closeKey = closeKey;
            this.n = n;
            SendOpenKeyToServer(openKey, n);
        }

        private void btRSA_Click(object sender, RoutedEventArgs e)
        {
            RSAmanipulations();
        }

        #endregion RSA

        #region Session

        byte[] sessionKey;

        private byte[] ParseSessionKey(string sessionKey)
        {
            string[] sessionKeyComponents = sessionKey.Split('-');

            List<byte> sessionKeyResult = new List<byte>();
            BigInteger bi;

            foreach (string item in sessionKeyComponents)
            {
                bi = new BigInteger(Convert.ToDouble(item));
                bi = BigInteger.Pow(bi, (int)closeKey);

                BigInteger n_ = new BigInteger((int)n);
                byte endNum = (byte)(bi % n_);
                sessionKeyResult.Add(endNum);
            }

            return sessionKeyResult.ToArray();
        }

        private byte[] SendSessionKey()
        {
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://localhost:44393/Home/GetSessionKey");
            request.Method = "Get";

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            using (Stream stream = response.GetResponseStream())
            {
                string sendingResult = "";
                using (StreamReader reader = new StreamReader(stream))
                {
                    string line = "";
                    while ((line = reader.ReadLine()) != null)
                        sendingResult += line;

                    string[] arr = sendingResult.Split('|');
                    if (!arr[0].Equals("OK"))
                    {
                        lMessage.Content = arr[1];
                        return null;
                    }
                    else
                    {
                        lMessage.Content = "";
                        return ParseSessionKey(arr[1]);
                    }
                }
            }
        }

        private void btSession_Click(object sender, RoutedEventArgs e)
        {
            SessionKeyManipulations();
        }

        private void SessionKeyManipulations()
        {
            this.sessionKey = SendSessionKey();
        }

        #endregion Session

        #region fileOpen

        public string AesDecrypt(byte[] ecryptedText)
        {
            byte[] bytes4part = new byte[16];
            byte[] bytes1_3parts = new byte[ecryptedText.Length - 16];
            for (int i = ecryptedText.Length - 16, j = 0; i < ecryptedText.Length; i++, j++)
                bytes4part[j] = ecryptedText[i];
            for (int i = 0; i < ecryptedText.Length - 16; i++)
                bytes1_3parts[i] = ecryptedText[i];
            Aes aes = Aes.Create();

            aes.Key = sessionKey;
            aes.IV = bytes4part;
            string text = "";
            byte[] data = bytes1_3parts;
            ICryptoTransform crypt = aes.CreateDecryptor(aes.Key, aes.IV);
            using (MemoryStream ms = new MemoryStream(data))
            {
                using (CryptoStream cs = new CryptoStream(ms, crypt, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        text = sr.ReadToEnd();
                    }
                }
            }
            return text;
        }

        private byte[] FromStringToByteArr(string str)
        {
            string[] strParts = str.Split('-');
            List<byte> bytes = new List<byte>();
            foreach (string elem in strParts)
                bytes.Add(Byte.Parse(elem));

            return bytes.ToArray();
        }

        private void btOpen_Click(object sender, RoutedEventArgs e)
        {
            string filename = tbFilename.Text;
            HttpWebRequest request = (HttpWebRequest)WebRequest.Create("https://localhost:44393/Home/GetText"
                + "?filename=" + filename);
            request.Method = "Get";

            HttpWebResponse response = (HttpWebResponse)request.GetResponse();
            using (Stream stream = response.GetResponseStream())
            {
                string textResult = "";
                using (StreamReader reader = new StreamReader(stream))
                {
                    string line = "";
                    while ((line = reader.ReadLine()) != null)
                        textResult += line;

                    string[] resultParts = textResult.Split('|');
                    if (!resultParts[0].Equals("OK"))
                    {
                        lMessage.Content = resultParts[1];
                    }
                    else
                    {
                        lMessage.Content = "";
                        tbText.Text = AesDecrypt(FromStringToByteArr(resultParts[1]));
                    }
                }
            }
        }

        #endregion fileOpen
    }
}


/*
 * Описание работы "Open_Click"
 * 
 * В системе на сервере хранится список имён доступных файлов
 * При включении сервера программа проходит по даным именам и сохраняет в файлы *filename*_encrypted
 * 
 * К: Беру имя файла
 * К: Отправляю запрос
 * С: Получает запрос
 * С: Ищет указанный файл в списке файлов
 * С: есл такого файла нет, то возвращает "Err|File does not exist"
 * С: если такой файл имеется, то:
 * С: Берёт зашифрованную версию, делает её строкой
 * С: Отправляет полученную строку в виде "OK|*строка*"
 */
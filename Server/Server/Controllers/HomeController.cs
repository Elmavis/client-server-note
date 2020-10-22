using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.Numerics;
using System.IO;
using System.Security.Cryptography;

namespace Server.Controllers
{
    public class HomeController : Controller
    {
        static long openKey;
        static long n;

        static byte[] sessionKey;

        static readonly string[] filenames = { "file1.txt", "file2.txt" };

        // GET: Home
        public ActionResult Index()
        {
            return View();
        }

        #region RSA

        //Принимает строку, чтобы можно было обработать ошибки неверного форматирования
        public ContentResult PostRSA(string openKey, string n)
        {
            try
            {
                HomeController.openKey = long.Parse(openKey);
                HomeController.n = long.Parse(n);
            }
            catch (Exception)
            {
                return Content("Error: format is illegal");
            }
            return Content("OK");
        }

        //По логике можно возвращать зашифрованный массив байтов и расшифровывать в клиенте
        private string RSAencrypt(byte[] sessionKey, long e, long n)
        {
            List<string> result = new List<string>();

            BigInteger bi;

            for (int i = 0; i < sessionKey.Length; i++)
            {
                bi = new BigInteger(sessionKey[i]);
                bi = BigInteger.Pow(bi, (int)e);

                BigInteger n_ = new BigInteger((int)n);
                bi %= n_;

                result.Add(bi.ToString());
            }
            string resultString = "";
            foreach (var item in result)
                resultString += item + "-";

            return resultString.Substring(0, resultString.Length - 1);
        }

        #endregion RSA

        #region SessionKey

        private byte[] GenerateSessionKey()
        {
            Aes aes = Aes.Create();
            aes.GenerateKey();
            return aes.Key;
        }

        private string EncryptSessionKey(byte[] sessionKey)
        {
            return RSAencrypt(sessionKey, openKey, n);
        }

        public ActionResult GetSessionKey()
        {
            HomeController.sessionKey = GenerateSessionKey();
            EncryptFiles();
            return Content("OK|" + EncryptSessionKey(HomeController.sessionKey).ToString());
        }

        #endregion SessionKey

        #region FileSending

        private string ByteArrayToString(byte [] arr)
        {
            string result = "";
            foreach(byte elem in arr)
            {
                result += elem + "-";
            }

            return result.Substring(0, result.Length - 1);
        }

        //возвращает массив байтов
        private byte[] EncryptText(string text)
        {
            return ToAes256(text); //TODO сделать нормальнье 
        }

        private void EncryptFiles()
        {
            foreach (var filename in filenames)
            {
                using (StreamReader sr = new StreamReader(Server.MapPath("App_Data\\" + filename)))
                {
                    string text = sr.ReadToEnd();
                    string encryptedText = ByteArrayToString(EncryptText(text));
                    string[] filenameParts = filename.Split('.');
                    string newFilename = filenameParts[0] + "_encrypted." + filenameParts[1];
                    using (StreamWriter sw = new StreamWriter(Server.MapPath("App_Data\\" + newFilename)))
                    {
                        sw.Write(encryptedText);
                    }
                }
            }
        }

        public static byte[] ToAes256(string src)
        {
            //Объявляем объект класса AES
            Aes aes = Aes.Create();
            //Генерируем соль
            aes.GenerateIV();
            //Присваиваем ключ. 
            aes.Key = HomeController.sessionKey;
            byte[] encrypted;
            ICryptoTransform crypt = aes.CreateEncryptor(aes.Key, aes.IV);
            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, crypt, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(src);
                    }
                }
                //Записываем в переменную encrypted зашиврованный поток байтов
                encrypted = ms.ToArray();
            }
            //Возвращаем поток байт + крепим соль
            return encrypted.Concat(aes.IV).ToArray();
        }

        public ActionResult GetText(string filename)
        {
            if (filenames.Contains(filename))
            {
                string[] filenameParts = filename.Split('.');
                string newFilename = filenameParts[0] + "_encrypted." + filenameParts[1];

                using (StreamReader sr = new StreamReader(Server.MapPath("App_Data\\" + newFilename)))
                {                    
                    string text = sr.ReadToEnd(); //уже зашифрован
                    return Content("OK|" + text);
                }
            }
            else
            {
                return Content("ERR|File does not exist");
            }
        }

        #endregion FileSending
    }
}

/*
* В системе на сервере хранится список имён доступных файлов
* При включении сервера программа проходит по даным именам и сохраняет в файлы *filename*_encrypted
* 
* К: Беру имя файла
* К: Отправляю запрос
* С: Получает запрос
* С: Ищет указанный файл в списке файлов
* С: есл такого файла нет, то возвращает "NEOK|File does not exist"
* С: если такой файл имеется, то:
* С: Берёт зашифрованную версию, делает её строкой
* С: Отправляет полученную строку в виде "OK|*строка*"
* 
*/
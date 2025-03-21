using Org.BouncyCastle.Bcpg.OpenPgp;
using Org.BouncyCastle.Bcpg;
using Org.BouncyCastle.Security;
using System;
using System.Collections.Generic;
using System.IO.Compression;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace EncriptarArchivo
{
    public static class PgpEncryptFile
    {
        //Se probo para llave ECDSA/EdDSA y RSA
        public static void EncryptFile(string inputFilePath, string outputFilePath, string publicKeyPath)
        {
            using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
            using (Stream outputFileStream = File.Create(outputFilePath))
            {
                PgpEncryptFile.EncryptFile(outputFileStream, inputFilePath, publicKeyStream, true, true);
            }
        }
        public static void EncryptFile(
                Stream outputStream,
                string fileName,
                Stream publicKeyStream,
                bool armor,
                bool withIntegrityCheck)
        {
            PgpPublicKey pubKey = ReadPublicKey(publicKeyStream);

            using (MemoryStream bOut = new MemoryStream())
            {
                PgpCompressedDataGenerator comData = new PgpCompressedDataGenerator(CompressionAlgorithmTag.Zip);

                using (Stream compressedOut = comData.Open(bOut))
                {
                    PgpUtilities.WriteFileToLiteralData(
                        compressedOut,
                        PgpLiteralData.Binary,
                        new FileInfo(fileName));
                } // Aquí se cierra el Stream directamente

                PgpEncryptedDataGenerator cPk = new PgpEncryptedDataGenerator(
                    SymmetricKeyAlgorithmTag.Cast5,
                    withIntegrityCheck,
                    new SecureRandom());

                cPk.AddMethod(pubKey);

                byte[] bytes = bOut.ToArray();

                if (armor)
                {
                    using (ArmoredOutputStream armoredStream = new ArmoredOutputStream(outputStream))
                    {
                        using (Stream cOut = cPk.Open(armoredStream, bytes.Length))
                        {
                            cOut.Write(bytes, 0, bytes.Length);
                        }
                    }
                }
                else
                {
                    using (Stream cOut = cPk.Open(outputStream, bytes.Length))
                    {
                        cOut.Write(bytes, 0, bytes.Length);
                    }
                }
            }
        }
        internal static void EncryptFiles(string[] inputFilePaths, string publicKeyPath)
        {
            // Mostrar un SaveFileDialog para seleccionar la ubicación y nombre del archivo ZIP
            using (SaveFileDialog saveFileDialog = new SaveFileDialog())
            {
                saveFileDialog.Filter = "ZIP Files|*.zip";
                saveFileDialog.Title = "Guardar archivo comprimido";
                saveFileDialog.FileName = "ArchivosComprimidos.zip"; // Nombre predeterminado

                if (saveFileDialog.ShowDialog() == DialogResult.OK)
                {
                    string zipPath = saveFileDialog.FileName;
                    string[] selectedFiles = inputFilePaths;

                    // Comprimir archivos en el ZIP sin usar CreateEntryFromFile
                    using (FileStream zipToOpen = new FileStream(zipPath, FileMode.Create))
                    using (ZipArchive archive = new ZipArchive(zipToOpen, ZipArchiveMode.Create))
                    {
                        foreach (string file in selectedFiles)
                        {
                            // Crear una entrada en el archivo ZIP
                            ZipArchiveEntry entry = archive.CreateEntry(Path.GetFileName(file));

                            // Copiar el contenido del archivo en la entrada del ZIP
                            using (FileStream fileToCompress = new FileStream(file, FileMode.Open, FileAccess.Read))
                            using (Stream entryStream = entry.Open())
                            {
                                fileToCompress.CopyTo(entryStream);
                            }
                        }
                    }

                    //MessageBox.Show("Archivos comprimidos exitosamente en " + zipPath);
                    //PgpEncrypt.EncryptFile(zipPath, zipPath + ".pgp", publicKeyPath);
                    using (Stream publicKeyStream = File.OpenRead(publicKeyPath))
                    using (Stream outputFileStream = File.Create(zipPath + ".pgp"))
                    {
                        EncryptFile(outputFileStream, zipPath, publicKeyStream, true, true);
                    }
                    File.Delete(zipPath);
                    MessageBox.Show("Se encriptaron todos los archivos juntos en: " + zipPath + ".pgp" + "\nCon la llave pública: " + publicKeyPath);
                }
            }
        }
        private static PgpPublicKey ReadPublicKey(Stream inputStream)
        {
            using (Stream input = PgpUtilities.GetDecoderStream(inputStream))
            {
                PgpPublicKeyRingBundle pgpPub = new PgpPublicKeyRingBundle(input);
                foreach (PgpPublicKeyRing kRing in pgpPub.GetKeyRings())
                {
                    foreach (PgpPublicKey k in kRing.GetPublicKeys())
                    {
                        if (k.IsEncryptionKey)
                        {
                            return k;
                        }
                    }
                }
            }
            throw new ArgumentException("No encryption key found in public key.");
        }
    }
}

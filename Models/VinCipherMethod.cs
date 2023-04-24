using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;


namespace EncryptionWebApp.Models
{
    public class VinCipherMethod
    {
        
    public VinCipherMethod()
        {
        }

        private static bool CheckIfEmptyString(string Text, string Key = "thisisakey") 
        {
                if (string.IsNullOrEmpty(Key) || string.IsNullOrWhiteSpace(Key)) {
                    return false;
            }
                if (string.IsNullOrEmpty(Text) || string.IsNullOrWhiteSpace(Text)) {
                    return false;
                }
                return true;
            }

        public static string Encrypt(string Text, string Key = "thisisakey") {
            try
            {
                string EncryptedText = "", CipheredText = "";

                int TNumValue,
                    KNumValue, 
                    ASCIIofa = 97, 
                    ASCIIofA = 65, 
                    lettersInAlphabet = 26; 

                if (CheckIfEmptyString(Key, Text))
                {

                    for (int i = 0, j = 0; i < Text.Length; i++)
                    {

                        if (Text.ElementAt(i) >= 'a' && Text.ElementAt(i) <= 'z')
                        {
                            KNumValue = ((int)(Key.ElementAt(j))) - ASCIIofa;
                            TNumValue = ((int)(Text.ElementAt(i))) - ASCIIofa;

                            j++;
                            j %= Key.Length;

                            TNumValue = (TNumValue + KNumValue) % lettersInAlphabet;
                            CipheredText += (char)(TNumValue + ASCIIofa);
                        }
                        else if (Text.ElementAt(i) >= 'A' && Text.ElementAt(i) <= 'Z')
                        { 

                            KNumValue = ((int)(Key.ElementAt(j))) - ASCIIofA;
                            TNumValue = ((int)(Text.ElementAt(i))) - ASCIIofA;

                            j++;
                            j %= Key.Length;

                            TNumValue = (TNumValue + KNumValue) % lettersInAlphabet;
                            CipheredText += (char)(TNumValue + ASCIIofA);
                        }
                        else
                        {
                            CipheredText += Text.ElementAt(i);
                        }
                    }
                    EncryptedText = CipheredText;
                    return EncryptedText;
                }
                else { return "Error: Key or Text value is blank."; }
            }
            catch (Exception E)
            {
                return "Error: " + E.Message;
            }
        }
    }
}
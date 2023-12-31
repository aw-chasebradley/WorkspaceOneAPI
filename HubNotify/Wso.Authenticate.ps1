﻿
$Code=@"
public class WindowsSecurityDialog
    {

       public string CaptionText { get; set; }
       public string MessageText { get; set; }

        [DllImport("ole32.dll")]
        public static extern void CoTaskMemFree(IntPtr ptr);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        private struct CREDUI_INFO
        {
            public int cbSize;
            public IntPtr hwndParent;
            public string pszMessageText;
            public string pszCaptionText;
            public IntPtr hbmBanner;
        }


        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        private static extern bool CredUnPackAuthenticationBuffer(int dwFlags,
                                                                   IntPtr pAuthBuffer,
                                                                   uint cbAuthBuffer,
                                                                   StringBuilder pszUserName,
                                                                   ref int pcchMaxUserName,
                                                                   StringBuilder pszDomainName,
                                                                   ref int pcchMaxDomainame,
                                                                   StringBuilder pszPassword,
                                                                   ref int pcchMaxPassword);

        [DllImport("credui.dll", CharSet = CharSet.Auto)]
        private static extern int CredUIPromptForWindowsCredentials(ref CREDUI_INFO notUsedHere,
                                                                     int authError,
                                                                     ref uint authPackage,
                                                                     IntPtr InAuthBuffer,
                                                                     uint InAuthBufferSize,
                                                                     out IntPtr refOutAuthBuffer,
                                                                     out uint refOutAuthBufferSize,
                                                                     ref bool fSave,
                                                                     int flags);



        public bool ValidateUser()
        {
            var credui = new CREDUI_INFO
                                     {
                                         pszCaptionText = CaptionText,
                                         pszMessageText = MessageText
                                     };
            credui.cbSize = Marshal.SizeOf(credui);
            uint authPackage = 0;
            IntPtr outCredBuffer;
            uint outCredSize;
            bool save = false;


            const int loginErrorCode = 1326;    //Login Failed
            var authError = 0;

            while (true)
            {




                var result = CredUIPromptForWindowsCredentials(ref credui,
                                                               authError,
                                                               ref authPackage,
                                                               IntPtr.Zero,
                                                               0,
                                                               out outCredBuffer,
                                                               out outCredSize,
                                                               ref save,
                                                               1 /* Generic */);

                var usernameBuf = new StringBuilder(100);
                var passwordBuf = new StringBuilder(100);
                var domainBuf = new StringBuilder(100);

                var maxUserName = 100;
                var maxDomain = 100;
                var maxPassword = 100;
                if (result == 0)
                {
                    if (CredUnPackAuthenticationBuffer(0, outCredBuffer, outCredSize, usernameBuf, ref maxUserName,
                                                       domainBuf, ref maxDomain, passwordBuf, ref maxPassword))
                    {
                        //TODO: ms documentation says we should call this but i can't get it to work
                        //SecureZeroMem(outCredBuffer, outCredSize);

                        //clear the memory allocated by CredUIPromptForWindowsCredentials 
                        CoTaskMemFree(outCredBuffer);
                        var networkCredential = new NetworkCredential()
                                                {
                                                    UserName = usernameBuf.ToString(),
                                                    Password = passwordBuf.ToString(),
                                                    Domain = domainBuf.ToString()
                                                };

                        //Dummy Code replace with true User Validation
                        if (networkCredential.UserName == "Bo" && networkCredential.Password == "1234")
                            return true;
                        else //login failed show dialog again with login error
                        {
                            authError = loginErrorCode;
                        }



                    }
                }
                else return false;


            }
        }
    }
"@
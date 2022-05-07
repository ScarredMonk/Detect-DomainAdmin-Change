using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;

namespace Detect_DomainAdmin_Change
{
    internal class Program
    {
        static List<KeyValuePair<string, string>> origGroupMembersList = new List<KeyValuePair<string, string>>();
        static void Main()
        {
            Console.ForegroundColor = ConsoleColor.Blue;
            Console.WriteLine("\r\n   _________________________________ ");
            Console.WriteLine("  |  _____________________________  |");
            Console.WriteLine("  | | Detect-Domain Admin- Change | |");
            Console.WriteLine("  | |_____________________________| |");
            Console.WriteLine("  |_________________________________|");
            Console.WriteLine("                   by @ScarredMonk\r\n");
            Console.ForegroundColor = ConsoleColor.Gray;

            try
            {
                Domain.GetCurrentDomain().ToString();
            }
            catch (Exception ex)
            {
                Console.ForegroundColor = ConsoleColor.Red;
                Console.WriteLine(ex.Message + "\n\nPlease run it inside the domain joined machine \n\n");
                Console.ForegroundColor = ConsoleColor.Gray;
                return;
            }

            //Saving all the members into the list
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("[+] Existing Domain Admins\n");
            Console.ForegroundColor = ConsoleColor.Gray;
            SaveGroupMembers("Domain Admins");

            //Checking for new account addition into the security group
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine("\n[+] Monitoring the change in Domain Admins group\n");
            Console.ForegroundColor = ConsoleColor.Gray;
            while (true)
            {
                GetGroupMembers("Domain Admins");
                Thread.Sleep(5000);
            }
        }

        static void SaveGroupMembers(string groupname)
        {
            PrincipalContext context = new PrincipalContext(ContextType.Domain, Domain.GetCurrentDomain().ToString());
            GroupPrincipal group = GroupPrincipal.FindByIdentity(context, IdentityType.Name, groupname);
            if (group != null)
            {

                foreach (Principal p in group.GetMembers(true))
                {
                    origGroupMembersList.Add(new KeyValuePair<string, string>(group.Name, p.Name));
                        Console.ForegroundColor = ConsoleColor.Red;
                        Console.WriteLine("[Old] - An account " + p.Name + " was added in the security group " + group.Name);
                        Console.ForegroundColor = ConsoleColor.Gray;
                }
                group.Dispose();
            }
        }
        static void GetGroupMembers(string groupname)
        {
            PrincipalContext ctx = new PrincipalContext(ContextType.Domain, Domain.GetCurrentDomain().ToString());
            GroupPrincipal group = GroupPrincipal.FindByIdentity(ctx, IdentityType.Name, groupname);

            if (group != null)
            {
                foreach (Principal p in group.GetMembers(true))
                {
                        var compareList = origGroupMembersList.Where(x => x.Key == group.Name && x.Value == p.Name);
                        if (!compareList.Any())
                        {
                            Console.ForegroundColor = ConsoleColor.Green;
                            Console.WriteLine("[New] - An account " + p.Name + " is added into the security group " + group.Name);
                            Console.ForegroundColor = ConsoleColor.Gray;

                            origGroupMembersList.Add(new KeyValuePair<string, string>(group.Name, p.Name));
                        }
                }
                group.Dispose();
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

class Program
{
    static string senhaMestra;
    static Dictionary<string, string> senhas;

    static void Main(string[] args)
    {
        senhas = new Dictionary<string, string>();

        Console.WriteLine("Bem-vindo(a) ao gerenciador de senhas!");

        Console.Write("Digite a senha mestra: ");
        senhaMestra = Console.ReadLine();

        while (true)
        {
            Console.WriteLine();
            Console.WriteLine("Opções:");
            Console.WriteLine("1. Adicionar uma nova senha");
            Console.WriteLine("2. Ver todas as senhas");
            Console.WriteLine("3. Buscar uma senha por serviço");
            Console.WriteLine("4. Remover uma senha");
            Console.WriteLine("5. Sair");

            Console.Write("Escolha uma opção: ");
            string opcao = Console.ReadLine();

            Console.WriteLine();

            switch (opcao)
            {
                case "1":
                    AdicionarSenha();
                    break;
                case "2":
                    VerTodasSenhas();
                    break;
                case "3":
                    BuscarSenhaPorServico();
                    break;
                case "4":
                    RemoverSenha();
                    break;
                case "5":
                    Console.WriteLine("Obrigado por utilizar o gerenciador de senhas!");
                    return;
                default:
                    Console.WriteLine("Opção inválida. Por favor, escolha uma opção válida.");
                    break;
            }
        }
    }

    static void AdicionarSenha()
    {
        Console.Write("Digite o nome do serviço: ");
        string servico = Console.ReadLine();

        if (senhas.ContainsKey(servico))
        {
            Console.WriteLine("Já existe uma senha cadastrada para este serviço.");
            return;
        }

        Console.Write("Digite a senha: ");
        string senha = Console.ReadLine();

        string senhaCriptografada = CriptografarSenha(senha);
        senhas[servico] = senhaCriptografada;

        Console.WriteLine("Senha adicionada com sucesso.");
    }

    static void VerTodasSenhas()
    {
        if (senhas.Count == 0)
        {
            Console.WriteLine("Não há senhas cadastradas.");
            return;
        }

        Console.WriteLine("Todas as senhas:");

        foreach (var senha in senhas)
        {
            Console.WriteLine($"Serviço: {senha.Key}");
        }
    }

    static void BuscarSenhaPorServico()
    {
        Console.Write("Digite o nome do serviço: ");
        string servico = Console.ReadLine();

        if (!senhas.ContainsKey(servico))
        {
            Console.WriteLine("Senha não encontrada para o serviço especificado.");
            return;
        }

        string senhaCriptografada = senhas[servico];
        string senhaDescriptografada = DescriptografarSenha(senhaCriptografada);

        Console.WriteLine($"Serviço: {servico}");
        Console.WriteLine($"Senha: {senhaDescriptografada}");
    }

    static void RemoverSenha()
    {
        Console.Write("Digite o nome do serviço: ");
        string servico = Console.ReadLine();

        if (!senhas.ContainsKey(servico))
        {
            Console.WriteLine("Senha não encontrada para o serviço especificado.");
            return;
        }

        senhas.Remove(servico);
        Console.WriteLine("Senha removida com sucesso.");
    }

    static string CriptografarSenha(string senha)
    {
        using (Aes aes = Aes.Create())
        {
            byte[] senhaBytes = Encoding.UTF8.GetBytes(senha);
            byte[] salt = Encoding.UTF8.GetBytes(senhaMestra);

            Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(senhaMestra, salt);
            aes.Key = rfc2898.GetBytes(32);
            aes.IV = rfc2898.GetBytes(16);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(senhaBytes, 0, senhaBytes.Length);
                }

                byte[] senhaCriptografadaBytes = memoryStream.ToArray();
                return Convert.ToBase64String(senhaCriptografadaBytes);
            }
        }
    }

    static string DescriptografarSenha(string senhaCriptografada)
    {
        using (Aes aes = Aes.Create())
        {
            byte[] senhaCriptografadaBytes = Convert.FromBase64String(senhaCriptografada);
            byte[] salt = Encoding.UTF8.GetBytes(senhaMestra);

            Rfc2898DeriveBytes rfc2898 = new Rfc2898DeriveBytes(senhaMestra, salt);
            aes.Key = rfc2898.GetBytes(32);
            aes.IV = rfc2898.GetBytes(16);

            using (MemoryStream memoryStream = new MemoryStream())
            {
                using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(senhaCriptografadaBytes, 0, senhaCriptografadaBytes.Length);
                }

                byte[] senhaBytes = memoryStream.ToArray();
                return Encoding.UTF8.GetString(senhaBytes);
            }
        }
    }
}

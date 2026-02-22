% =========================================================================
%  extract.m — Chargement des traces EM et extraction des métadonnées
%
%  Lit les fichiers CSV de la campagne SECU8917 et produit :
%    L.mat       — Matrice des traces EM (Ntraces × Ns)
%    key_dec.mat — Clé de chiffrement (Ntraces × 16, décimal)
%    pti_dec.mat — Texte clair (Ntraces × 16, décimal)
%    cto_dec.mat — Texte chiffré (Ntraces × 16, décimal)
%
%  Ce script doit être exécuté UNE SEULE FOIS avant analyse.m.
% =========================================================================
clear all; clc; close all;
warning off;

%% Chargement des traces EM
folderSrc = 'SECU8917';

matrixFilelist = dir(fullfile(folderSrc, 'trace_AES_*.csv'));
Nfiles = length(matrixFilelist);
fprintf('Fichiers trouvés : %d\n', Nfiles);

firstTrace = csvread(fullfile(folderSrc, matrixFilelist(1).name));
Ns = length(firstTrace);
fprintf('Échantillons par trace : %d\n', Ns);

Ntraces = Nfiles;
L = zeros(Ntraces, Ns);
L(1,:) = firstTrace;

for i = 2:Ntraces
    L(i,:) = csvread(fullfile(folderSrc, matrixFilelist(i).name));
    if mod(i, 2000) == 0
        fprintf('  %d/%d traces chargées\n', i, Ntraces);
    end
end

fprintf('Matrice L : %d × %d\n', size(L,1), size(L,2));
save('L.mat', 'L', '-v7.3');
fprintf('L.mat sauvegardé.\n');

%% Extraction de key, pli, cto depuis les noms de fichiers
% Format : trace_AES_..._key=XXXX_pti=XXXX_cto=XXXX.csv
key_dec = zeros(Ntraces, 16);
pti_dec = zeros(Ntraces, 16);
cto_dec = zeros(Ntraces, 16);

for i = 1:Ntraces
    name = matrixFilelist(i).name;
    tokens = regexp(name, 'key=(\w+)_pti=(\w+)_cto=(\w+)\.csv', 'tokens');
    key_hex = tokens{1}{1};
    pti_hex = tokens{1}{2};
    cto_hex = tokens{1}{3};

    for j = 1:16
        key_dec(i,j) = hex2dec(key_hex(2*j-1 : 2*j));
        pti_dec(i,j) = hex2dec(pti_hex(2*j-1 : 2*j));
        cto_dec(i,j) = hex2dec(cto_hex(2*j-1 : 2*j));
    end
end

save('key_dec.mat', 'key_dec');
save('pti_dec.mat', 'pti_dec');
save('cto_dec.mat', 'cto_dec');
fprintf('key_dec, pti_dec, cto_dec sauvegardés.\n');

% =========================================================================
%  dec.m — Attaque EMA sur AES-128 (dernier round)
% =========================================================================
clear all; clc; close all;
warning off;
addpath('squelettes/squelettes');

% Chargement des données (générées par extract.m)
load('L.mat');           % Traces EM : Ntraces × Ns
load('cto_dec.mat');     % Chiffré (décimal) : Ntraces × 16
load("pti_dec.mat");     % Texte clair (décimal) : Ntraces × 16
aide;                    % Tables AES : SBox, invSBox, shiftrow, Weight_Hamming_vect

[Ntraces, Ns] = size(L);
fprintf('Campagne : %d traces de %d échantillons\n\n', Ntraces, Ns);



%% ====================================================================
%  SELECTION DE LA FENETRE DU DERNIER ROUND
%  ====================================================================

atk_win = 3069:min(3268, Ns); % à modifier lors de l'usage avec des fuites différentes
L_win   = L(:, atk_win);


%% ====================================================================
%  ATTAQUE CPA — CORRELATION DE PEARSON
%  ====================================================================

% Pour chaque octet b :
%   1. z = InvSBox(CTO(b) XOR k)
%   2. HD = HW(z XOR CTO(shiftrow(b)))
%   3. Corrélation de Pearson entre HD et les traces
%   4. Meilleure hypothèse = max |corrélation|

K10_cpa  = zeros(1, 16);
rank_cpa = zeros(1, 16);

for byte = 1:16
    % Hypothèses : 256 sous-clés pour cet octet
    CTO_byte = uint8(cto_dec(:, byte));
    CTO_rep  = repmat(CTO_byte, 1, 256);
    K_rep    = repmat(uint8(0:255), Ntraces, 1);

    % z = InvSBox(CTO XOR k)
    V_hyp = invSBox(double(bitxor(CTO_rep, K_rep)) + 1);

    % HD = HW(z XOR ShiftRows(CTO)(byte))
    CTO_sr = uint8(cto_dec(:, shiftrow(byte)));
    HD_hyp = double(Weight_Hamming_vect(bitxor(uint8(V_hyp), repmat(CTO_sr, 1, 256)) + 1));

    % Corrélation de Pearson sur la fenêtre d'attaque (256 × Npts)
    C = mycorr(HD_hyp, L_win);

    % Score : somme des carrés des 5 meilleures corrélations (en valeur absolue)
    C_sorted = sort(abs(C), 2, 'descend');
    score = sum(C_sorted(:, 1:5).^2, 2);
    [~, idx_k] = max(score);
    K10_cpa(byte) = idx_k - 1;

    
end

% Vérifiaction de la clé trouvée
K10_hex = reshape(dec2hex(uint8(K10_cpa),2).',1,[]);
res = verify(K10_hex, reshape(dec2hex(uint8(cto_dec(1,:)),2).',1,[]) , reshape(dec2hex(uint8(pti_dec(1,:)),2).',1,[]));

if res == 1 % Clé trouvée
    tmp = cell(1,11);
    [tmp{:}] = decipher_key(K10_hex);
    keys = vertcat(tmp{:});
    fprintf('\nClé et sous-clés trouvées\n')
    for i = 1:size(keys,1)
        fprintf('Clé %02d : %s\n', i-1, keys(i,:));
    end

else % Clé non trouvée
    fprintf('\nClé non trouvée\n')
end


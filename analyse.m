% =========================================================================
%  analyse.m — Attaque EMA sur AES-128 (dernier round)
% =========================================================================
clear all; clc; close all;
warning off;
addpath('squelettes/squelettes');

% Chargement des données (générées par extract.m)
load('L.mat');           % Traces EM : Ntraces × Ns
load('cto_dec.mat');     % Chiffré (décimal) : Ntraces × 16
load('key_dec.mat');     % Clé (décimal) : Ntraces × 16
aide;                    % Tables AES : SBox, invSBox, shiftrow, Weight_Hamming_vect

[Ntraces, Ns] = size(L);
fprintf('Campagne : %d traces de %d échantillons\n\n', Ntraces, Ns);

%% ====================================================================
%  Q1 : TRACE INDIVIDUELLE
%  ====================================================================
figure;
plot(L(1,:));
title('Q1 : Trace EM individuelle (trace n°1)');
xlabel('Échantillon');
ylabel('Amplitude EM');
saveas(gcf, 'fig_q1.png');

%% ====================================================================
%  Q2 : TRACE MOYENNE — IDENTIFICATION DES ROUNDS
%  ====================================================================
figure;
plot(mean(L, 1));
title('Q2 : Trace EM moyenne (20 000 traces)');
xlabel('Échantillon');
ylabel('Amplitude EM moyenne');
saveas(gcf, 'fig_q2.png');
% → 10 rounds visibles. Le dernier round se situe entre ~3050 et ~3280.

%% ====================================================================
%  Q3 : VALIDATION DU MODELE HAMMING DISTANCE (DERNIER ROUND)
%  ====================================================================
% Le round 10 de l'AES-128 ne comporte pas de MixColumns :
%     C = ShiftRows(SubBytes(State_in)) XOR K10
%
% En inversant depuis le chiffré C :
%     z(b) = InvSBox( C(b) XOR K10(b) )  →  donne state_9(shiftrow(b))
%
% Le modèle de fuite est la distance de Hamming entre l'état avant
% et après le dernier round dans le registre :
%     HD(b) = HW( z(b) XOR ShiftRows(C)(b) )
%           = HW( InvSBox(C(b) XOR K10(b)) XOR C(shiftrow(b)) )
%
% Validation : on calcule la corrélation de Pearson entre HD (avec
% la vraie clé K10) et les traces EM.

% Calcul de K10 par expansion de clé (key schedule AES-128)
key4x4  = uint32(reshape(key_dec(1,:), 4, 4));
all_w   = keysched2(key4x4);
K10     = double(all_w(:,:,11));   % Sous-clé du round 10
K10_vec = K10(:)';                 % Vecteur linéaire 1×16

% z = InvSBox(CTO XOR K10)
z_valid = invSBox(double(bitxor(uint8(cto_dec), uint8(repmat(K10_vec, Ntraces, 1)))) + 1);

% ShiftRows(CTO) : pour chaque octet b, prendre cto(:, shiftrow(b))
cto_shifted = cto_dec(:, shiftrow);

% HD = HW(z XOR ShiftRows(CTO))
HD_valid = Weight_Hamming_vect(bitxor(uint8(z_valid), uint8(cto_shifted)) + 1);

% Corrélation de Pearson : HD vs traces (16 × Ns)
cor_valid = mycorr(double(HD_valid), L);

figure;
plot(cor_valid');
title('Q3 : Corrélation HD(z, ShiftRows(CTO)) vs traces EM (clé connue)');
xlabel('Échantillon');
ylabel('Corrélation de Pearson');
saveas(gcf, 'fig_q3.png');

%% ====================================================================
%  Q4 : REPRESENTATION 4×4 DECIMALE DE LA CLE K10
%  ====================================================================
fprintf('=== Q4 : Clé du dernier round K10 ===\n');
fprintf('Format 4×4 (décimal) :\n');
disp(K10);
fprintf('Format linéaire (hex) : ');
fprintf('%02X ', K10_vec);
fprintf('\n\n');

%% ====================================================================
%  Q5 : SELECTION DE LA FENETRE DU DERNIER ROUND
%  ====================================================================
% La corrélation Q3 montre que l'information fuit entre ~2200 et ~3500.
% On restreint l'attaque à cette fenêtre pour optimiser la vitesse.
atk_win = 3069:min(3268, Ns);
L_win   = L(:, atk_win);

fprintf('Q5 : Fenêtre d''attaque : [%d, %d] (%d points)\n\n', ...
    atk_win(1), atk_win(end), length(atk_win));

% Figure justificative du choix de fenêtre
figure;
subplot(2,1,1);
trace_moy = mean(L, 1);
plot(trace_moy, 'b'); hold on;
yl = ylim;
fill([atk_win(1) atk_win(end) atk_win(end) atk_win(1)], ...
     [yl(1) yl(1) yl(2) yl(2)], 'r', 'FaceAlpha', 0.15, 'EdgeColor', 'r', 'LineWidth', 1.5);
title('Trace EM moyenne — fenêtre d''attaque');
xlabel('Échantillon'); ylabel('Amplitude EM');
legend('Trace moyenne', sprintf('Fenêtre [%d, %d]', atk_win(1), atk_win(end)));
hold off;

subplot(2,1,2);
plot(max(abs(cor_valid), [], 1), 'b'); hold on;
yl2 = ylim;
fill([atk_win(1) atk_win(end) atk_win(end) atk_win(1)], ...
     [yl2(1) yl2(1) yl2(2) yl2(2)], 'r', 'FaceAlpha', 0.15, 'EdgeColor', 'r', 'LineWidth', 1.5);
title('Max |corrélation HD| sur les 16 octets — fenêtre d''attaque');
xlabel('Échantillon'); ylabel('Max |\rho|');
legend('Max corr. HD', sprintf('Fenêtre [%d, %d]', atk_win(1), atk_win(end)));
hold off;
saveas(gcf, 'fig_fenetre.png');

%% ====================================================================
%  Q6-Q7 : HYPOTHESES DE CLE ET VALEURS INTERMEDIAIRES
%  ====================================================================
% Pour chaque octet b (1..16), chaque hypothèse k (0..255), chaque trace i :
%     z(i, k+1, b) = InvSBox( CTO(i, b) XOR k )
%     HD(i, k+1, b) = HW( z(i, k+1, b) XOR CTO(i, shiftrow(b)) )
%
% Le modèle Hamming Distance capture la transition du registre entre
% l'état avant le dernier round (state_9) et le chiffré.

%% ====================================================================
%  Q8a : ATTAQUE CPA — CORRELATION DE PEARSON
%  ====================================================================
% La CPA calcule la corrélation de Pearson entre le modèle HD et les
% traces EM pour chaque hypothèse de clé.
%
% Pour chaque octet b :
%   1. z = InvSBox(CTO(b) XOR k)
%   2. HD = HW(z XOR CTO(shiftrow(b)))
%   3. Corrélation de Pearson entre HD et les traces
%   4. Meilleure hypothèse = max |corrélation|

fprintf('=== Q8a : CPA (Hamming Distance) ===\n');

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

    % Rang de la vraie clé
    true_k = K10_vec(byte);
    rank_cpa(byte) = sum(score > score(true_k + 1)) + 1;

    tag = 'FAIL'; if rank_cpa(byte) == 1, tag = 'OK  '; end
    fprintf('  Octet %2d : 0x%02X (attendu 0x%02X) | Rang %d [%s]\n', ...
        byte, K10_cpa(byte), true_k, rank_cpa(byte), tag);
end

fprintf('\nClé trouvée (CPA) : '); fprintf('%02X ', K10_cpa); fprintf('\n');
fprintf('Clé attendue      : '); fprintf('%02X ', K10_vec); fprintf('\n');
fprintf('Score : %d/16 octets | GE = %.2f\n\n', ...
    sum(K10_cpa == K10_vec), mean(rank_cpa));

%% ====================================================================
%  Q8b : ATTAQUE DPA — DIFFERENCE DE MOYENNES (ORDRE 1)
%  ====================================================================
% La DPA partitionne les traces en deux classes selon le LSB de la
% valeur intermédiaire z, puis mesure la différence de moyennes.
%
% Pour chaque hypothèse k :
%   1. z = InvSBox(CTO XOR k)
%   2. Partitionner les traces selon bitget(z, 1)  (LSB)
%   3. DPA(k,t) = mean(L | LSB=1) - mean(L | LSB=0)
%   4. Score(k) = max_t |DPA(k,t)|

fprintf('=== Q8b : DPA (ordre 1, LSB de z) ===\n');

K10_dpa  = zeros(1, 16);
rank_dpa = zeros(1, 16);
L_win_sum = sum(L_win, 1);

for byte = 1:16
    CTO_byte = uint8(cto_dec(:, byte));
    CTO_rep  = repmat(CTO_byte, 1, 256);
    K_rep    = repmat(uint8(0:255), Ntraces, 1);

    % z = InvSBox(CTO XOR k)
    V_hyp = invSBox(double(bitxor(CTO_rep, K_rep)) + 1);

    % Partition sur le LSB de z (1 seul bit, pas de cumul)
    S  = double(bitget(uint8(V_hyp), 1));
    N1 = sum(S, 1)';
    N0 = Ntraces - N1;

    class1 = S' * L_win;
    class0 = repmat(L_win_sum, 256, 1) - class1;
    DPA    = class1 ./ N1 - class0 ./ N0;

    dpa_score = max(abs(DPA), [], 2);

    [~, idx_k] = max(dpa_score);
    K10_dpa(byte) = idx_k - 1;

    true_k = K10_vec(byte);
    rank_dpa(byte) = sum(dpa_score > dpa_score(true_k + 1)) + 1;

    tag = 'FAIL'; if rank_dpa(byte) == 1, tag = 'OK  '; end
    fprintf('  Octet %2d : 0x%02X (attendu 0x%02X) | Rang %d [%s]\n', ...
        byte, K10_dpa(byte), true_k, rank_dpa(byte), tag);
end

fprintf('\nClé trouvée (DPA) : '); fprintf('%02X ', K10_dpa); fprintf('\n');
fprintf('Clé attendue      : '); fprintf('%02X ', K10_vec); fprintf('\n');
fprintf('Score : %d/16 octets | GE = %.2f\n\n', ...
    sum(K10_dpa == K10_vec), mean(rank_dpa));

%% ====================================================================
%  Q9 : GUESSING ENTROPY — CONVERGENCE VS NOMBRE DE TRACES
%  ====================================================================
% La Guessing Entropy (GE) mesure le rang moyen de la vraie clé parmi
% les 256 hypothèses, moyenné sur les 16 octets.
%   GE = 1 → clé retrouvée pour tous les octets
%   GE > 1 → certains octets ne sont pas encore résolus
%
% On étudie la convergence de la GE en fonction du nombre de traces
% utilisées pour l'attaque CPA (ordre 2).

fprintf('=== Q9 : Convergence Guessing Entropy (CPA-HD) ===\n');

steps = 1000:1000:Ntraces;
GE_cpa = zeros(1, length(steps));

for s = 1:length(steps)
    Nt = steps(s);
    ranks_sum = 0;

    for byte = 1:16
        CTO_byte = uint8(cto_dec(1:Nt, byte));
        CTO_rep  = repmat(CTO_byte, 1, 256);
        K_rep    = repmat(uint8(0:255), Nt, 1);

        V_hyp  = invSBox(double(bitxor(CTO_rep, K_rep)) + 1);
        CTO_sr = uint8(cto_dec(1:Nt, shiftrow(byte)));
        HD_hyp = double(Weight_Hamming_vect(bitxor(uint8(V_hyp), repmat(CTO_sr, 1, 256)) + 1));

        C = mycorr(HD_hyp, L(1:Nt, atk_win));
        C_sorted = sort(abs(C), 2, 'descend');
        score_ge = sum(C_sorted(:, 1:5).^2, 2);

        true_k = K10_vec(byte);
        rank = sum(score_ge > score_ge(true_k + 1)) + 1;
        ranks_sum = ranks_sum + rank;
    end

    GE_cpa(s) = ranks_sum / 16;
    fprintf('  %5d traces → GE = %.2f\n', Nt, GE_cpa(s));
end

figure;
plot(steps, GE_cpa, '-o', 'LineWidth', 2);
grid on;
title('Q9 : Guessing Entropy vs nombre de traces (CPA)');
xlabel('Nombre de traces');
ylabel('Rang moyen (GE)');
ylim([0, max(GE_cpa) * 1.1]);
saveas(gcf, 'fig_q9.png');

% Nombre minimal de traces pour GE = 1
idx_conv = find(GE_cpa == 1, 1, 'first');
if ~isempty(idx_conv)
    fprintf('\nConvergence GE = 1 atteinte à %d traces.\n', steps(idx_conv));
    fprintf('Optimisation : %d traces suffisent (%.0f%% de la campagne).\n', ...
        steps(idx_conv), 100*steps(idx_conv)/Ntraces);
end

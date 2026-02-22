function C = mycorr(A, B)
% MYCORR Corrélation de Pearson entre colonnes de A et colonnes de B
%   A : n x p, B : n x q -> C : p x q
    A = A - mean(A);
    B = B - mean(B);
    C = (A' * B) ./ sqrt(sum(A.^2)' * sum(B.^2));
end
